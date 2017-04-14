#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <dlfcn.h>

#include <sys/prctl.h>

//FILE *logfp = NULL;

extern char **environ;

struct worker
{
	bool is_in_use;
	int worker_index;
	pid_t pid;

	int fd_stdin[2];
	int fd_stdout[2];

	int sockfd;
	pthread_t reactor_thread;
	char source_address[INET_ADDRSTRLEN];
};

#define EXTEND_FD(fdcount, fdset, sockfd) { \
		FD_SET((sockfd), &(fdset)); \
		if((sockfd) >= fdcount) { \
			fdcount = (sockfd)+1; \
		} \
	}

const int worker_count = 16;

struct worker *worker_pool;

void *worker_lib;
int (*f_task_main)(int argc, char *argv[]);

pthread_mutex_t accept_mutex;

bool send_all(int sockfd, const char *buf, size_t len)
{
	size_t i = 0;
	while(i < len) {
		ssize_t written = send(sockfd, buf+i, len-i, 0);
		if(written <= 0) {
			return false;
		}
		i += written;
	}

	return true;
}

bool write_all(int sockfd, const char *buf, size_t len)
{
	size_t i = 0;
	while(i < len) {
		ssize_t written = write(sockfd, buf+i, len-i);
		if(written <= 0) {
			return false;
		}
		i += written;
	}

	return true;
}

void *reactor_func(void *Wvoid)
{
	struct worker *W = (struct worker *)Wvoid;
	pid_t my_pid = getpid();

	char buf_recv_write[8192];
	char buf_send_read[8192];
	size_t buf_recv_write_used = 0;
	size_t buf_send_read_used = 0;

	int fd_recv = W->sockfd;
	int fd_read = W->fd_stdout[0];
	int fd_send = W->sockfd;
	int fd_write = W->fd_stdin[1];

	// Calculate nfds
	int nfds_r = (fd_recv > fd_read ? fd_recv : fd_read)+1;
	int nfds_w = (fd_send > fd_write ? fd_send : fd_write)+1;
	int nfds = (nfds_r > nfds_w ? nfds_r : nfds_w);

	fprintf(stderr, "%d: bufs %d %d\n", my_pid, (int)buf_recv_write_used, (int)buf_send_read_used);
	for(;;) {
		// Set read FDs
		fd_set readfds;
		FD_ZERO(&readfds);
		if(buf_recv_write_used < sizeof(buf_recv_write)) {
			FD_SET(fd_recv, &readfds);
		}
		if(buf_send_read_used < sizeof(buf_send_read)) {
			FD_SET(fd_read, &readfds);
		}

		// Set write FDs
		fd_set writefds;
		FD_ZERO(&writefds);
		FD_SET(fd_write, &writefds);
		FD_SET(fd_send, &writefds);

		// Do select
		int selcount = select(nfds, &readfds, &writefds, NULL, NULL);
		if(selcount <= 0) {
			perror("select");
			break;
		}

		// Do reads
		if(FD_ISSET(fd_recv, &readfds)) {
			ssize_t bs = recv(fd_recv,
				buf_recv_write + buf_recv_write_used,
				sizeof(buf_recv_write) - buf_recv_write_used,
				0);
			if(bs <= 0) {
				perror("recv");
				break;
			}
			assert(bs > 0);
			buf_recv_write_used += (size_t)bs;
		}
		if(FD_ISSET(fd_read, &readfds)) {
			fprintf(stderr, "%d: read %d\n", my_pid, (int)buf_send_read_used);
			ssize_t bs = read(fd_read,
				buf_send_read + buf_send_read_used,
				sizeof(buf_send_read) - buf_send_read_used);
			if(bs <= 0) {
				perror("read");
				break;
			}
			buf_send_read_used += (size_t)bs;
			fprintf(stderr, "%d: read complete %d\n", my_pid, (int)buf_send_read_used);
		}

		// Do writes
		if(buf_send_read_used > 0 && FD_ISSET(fd_send, &writefds)) {
			fprintf(stderr, "%d: send %d\n", my_pid, (int)buf_send_read_used);
			ssize_t bs = send(fd_send,
				buf_send_read,
				buf_send_read_used,
				0);
			if(bs <= 0) {
				perror("send");
				break;
			}

			if((size_t)bs != buf_send_read_used) {
				memmove(buf_send_read,
					buf_send_read + (size_t)bs,
					buf_send_read_used - (size_t)bs);
			}

			buf_send_read_used -= (size_t)bs;
		}
		if(buf_recv_write_used > 0 && FD_ISSET(fd_write, &writefds)) {
			ssize_t bs = write(fd_write,
				buf_recv_write,
				buf_recv_write_used);
			if(bs <= 0) {
				perror("write");
				break;
			}

			if((size_t)bs != buf_recv_write_used) {
				memmove(buf_recv_write,
					buf_recv_write + (size_t)bs,
					buf_recv_write_used - (size_t)bs);
			}

			buf_recv_write_used -= (size_t)bs;
		}
	}

	// Flush
	fprintf(stderr, "Flush!\n");
	while(buf_recv_write_used != 0 || buf_send_read_used != 0) {
		// Set write FDs
		fd_set writefds;
		FD_ZERO(&writefds);
		FD_SET(fd_write, &writefds);
		FD_SET(fd_send, &writefds);

		// Do select
		int selcount = select(nfds_w, NULL, &writefds, NULL, NULL);
		if(selcount <= 0) {
			perror("select");
			break;
		}

		// Do writes
		if(buf_send_read_used > 0 && FD_ISSET(fd_send, &writefds)) {
			fprintf(stderr, "%d: send cleanup %d\n", my_pid, (int)buf_send_read_used);
			ssize_t bs = send(fd_send,
				buf_send_read,
				buf_send_read_used,
				0);
			if(bs <= 0) {
				perror("send");
				buf_send_read_used = 0;
			} else {
				if((size_t)bs != buf_send_read_used) {
					memmove(buf_send_read,
						buf_send_read + (size_t)bs,
						buf_send_read_used - (size_t)bs);
				}

				buf_send_read_used -= (size_t)bs;
			}
		}
		if(buf_recv_write_used > 0 && FD_ISSET(fd_write, &writefds)) {
			ssize_t bs = write(fd_write,
				buf_recv_write,
				buf_recv_write_used);
			if(bs <= 0) {
				perror("write");
				buf_recv_write_used = 0;
			} else {
				if((size_t)bs != buf_recv_write_used) {
					memmove(buf_recv_write,
						buf_recv_write + (size_t)bs,
						buf_recv_write_used - (size_t)bs);
				}

				buf_recv_write_used -= (size_t)bs;
			}
		}
	}

	fprintf(stderr, "%d: Joined\n", my_pid);

	return NULL;
}

void spawn_worker(struct worker *W, int base_sockfd)
{
	assert(!W->is_in_use);

	pid_t child = fork();
	if(child != 0) {
		W->pid = child;
		return;
	}

	//
	// Child thread
	//

	prctl(PR_SET_NAME, (unsigned long)"c-runo: worker", 0, 0, 0);
	pid_t my_pid = getpid();

	// Loop
	for(;;)
	{
		struct sockaddr_in cli_addr;
		socklen_t cli_addrlen;

		// Set up pipes and dupe
		W->fd_stdin[0] = -1; W->fd_stdin[1] = -1;
		W->fd_stdout[0] = -1; W->fd_stdout[1] = -1;
		int did_stdin = pipe(W->fd_stdin);
		int did_stdout = pipe(W->fd_stdout);
		assert(did_stdin == 0);
		assert(did_stdout == 0);
		int did_stdin_2 = dup2(W->fd_stdin[0], STDIN_FILENO);
		int did_stdout_2 = dup2(W->fd_stdout[1], STDOUT_FILENO);
		assert(did_stdout_2 >= 0);
		assert(did_stdin_2 >= 0);

		// Accept connection
		cli_addrlen = sizeof(cli_addr);
		fprintf(stderr, "Accepting...\n");
		//pthread_mutex_lock(&accept_mutex);
		int cli_sockfd = accept(base_sockfd, (struct sockaddr *)&cli_addr, &cli_addrlen);
		//pthread_mutex_unlock(&accept_mutex);
		fprintf(stderr, "Accepted\n");
		assert(cli_sockfd >= 0);
		W->sockfd = cli_sockfd;

		// Get address
		const char *err_ntop = inet_ntop(AF_INET,
			&cli_addr.sin_addr, W->source_address, cli_addrlen);
		assert(err_ntop != NULL);

		// Process request
		fprintf(stderr, "%d: Start Request \"%s\"\n", my_pid, W->source_address);
		char *args[] = {
			"./worker",
			W->source_address,

			NULL
		};

		// Run reactor slave
		fflush(stdout);
		int err_reactor = pthread_create(&W->reactor_thread, NULL, reactor_func, (void *)W);
		assert(err_reactor == 0);
		f_task_main(2, args);
		fflush(stdout);
		shutdown(cli_sockfd, SHUT_RD);
		int err_join = pthread_join(W->reactor_thread, NULL);
		assert(err_join == 0);
		close(cli_sockfd);

		fprintf(stderr, "End Request\n");

		// Close pipes
		close(W->fd_stdin[0]);
		close(W->fd_stdin[1]);
		close(W->fd_stdout[0]);
		close(W->fd_stdout[1]);
	}
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	// Ignore SIGPIPE
	//signal(SIGPIPE, SIG_IGN);

	// Load lib
	worker_lib = dlopen(argv[1], RTLD_NOW);
	assert(worker_lib != NULL);
	*(void **)&f_task_main = dlsym(worker_lib, "task_main");
	assert(f_task_main != NULL);

	// Open log
	//logfp = fopen("out.log", "wb");

	// Create socket
	int base_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	int val_reuseaddr = 1;
	int err_reuseaddr = setsockopt(base_sockfd, SOL_SOCKET, SO_REUSEADDR,
		&val_reuseaddr, sizeof(val_reuseaddr));
	assert(err_reuseaddr == 0);

	// Bind port
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8000);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int err_bind = bind(base_sockfd, (struct sockaddr *)&addr, sizeof(addr));
	perror("bind");
	assert(err_bind == 0);
	int err_listen = listen(base_sockfd, worker_count*2+2); // Give a modest backlog for now
	perror("listen");
	assert(err_listen == 0);

	// Create workers
	worker_pool = calloc(1, sizeof(worker_pool[0])*worker_count);
	for(int i = 0; i < worker_count; i++) {
		spawn_worker(&worker_pool[i], base_sockfd);
	}

	// Set process name
	prctl(PR_SET_NAME, (unsigned long)"c-runo: master", 0, 0, 0);

	// Feed the reactor
	for(;;)
	{
		int wstatus = 0;
		pid_t pid = wait(&wstatus);
		//pid_t pid = waitpid(worker_pool[0].pid, &wstatus, 0);
		fprintf(stderr, "WAIT STATUS: %d %08X\n", pid, wstatus);
		abort();
	}

	//fclose(logfp);

	return 0;
}

