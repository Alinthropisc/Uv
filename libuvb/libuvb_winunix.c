#include <assert.h>

#include "libuvb.h"
#include "libuvb_winunix.h"


/* The background thread that reads and buffers the true stdin. */
static HANDLE stdin_thread = NULL;
static SOCKET socket_r = INVALID_SOCKET;

struct win_thread_data {
/* This is a copy of the true stdin file handle before any redirection. It is
   read by the thread. */
  HANDLE stdin_handle;
/* This is the listen socket for the thread. It is closed after the first
   connection. */
  int socket_l;
};

/* This is the thread that reads from the true stdin (tdata->stdin_handle) and
   writes to socket_w, which is connected to the replacement stdin that the rest of
   the program sees. Once started, it never finishes except in case of error.
   win_stdin_start_thread is responsible for setting up tdata->stdin_handle. */
static DWORD WINAPI win_stdin_thread_func(void *data)
{
    struct win_thread_data *tdata = (struct win_thread_data *)data;
    DWORD n, nwritten;
    char buffer[BUFSIZ];
    SOCKET socket_w = accept(tdata->socket_l, NULL, NULL);

    if (socket_w == INVALID_SOCKET)
    {
        //fprintf(stderr, "accept error: %d\n", socket_errno());
        goto ThreadCleanup;
    }

    closesocket(tdata->socket_l);
    tdata->socket_l = INVALID_SOCKET;

    for (;;)
    {
        if (ReadFile(tdata->stdin_handle, buffer, sizeof(buffer), &n, NULL) == 0)
        {
            break;
        }

        if (n == -1 || n == 0)
        {
            break;
        }
        // In the future, we can use WSASend to take advantage of the OVERLAPPED socket for IOCP
        nwritten = send(socket_w, buffer, n, 0);

        if (nwritten == SOCKET_ERROR)
        {
            break;
        }
        if (nwritten != n)
        {
            break;
        }
    }
ThreadCleanup:
    CloseHandle(tdata->stdin_handle);
    tdata->stdin_handle = NULL;

    if (tdata->socket_l != INVALID_SOCKET)
    {
        closesocket(tdata->socket_l);
        tdata->socket_l = INVALID_SOCKET;
    }
    if (socket_w != INVALID_SOCKET)
    {
        closesocket(socket_w);
    }
    return 0;
}

/* Get the newline translation mode (_O_TEXT or _O_BINARY) of a file
   descriptor. _O_TEXT does CRLF-LF translation and _O_BINARY does none.
   Complementary to _setmode. */
static int _getmode(int fd)
{
    int mode;

    /* There is no standard _getmode function, but _setmode returns the
       previous value. Set it to a dummy value and set it back. */
    mode = _setmode(fd, _O_BINARY);
    _setmode(fd, mode);
    return mode;
}

/* Start the reader thread and do all the file handle/descriptor redirection.
   Returns the STDIN socket on success, INVALID_SOCKET on error. */
int win_stdin_start_thread(void)
{
    int stdin_fd;
    int stdin_fmode;
    int rc = 0, socksize = 0;
    struct win_thread_data *tdata = NULL;
    SOCKADDR_IN selfaddr;

    if (socket_r != INVALID_SOCKET)
    {
        assert(stdin_thread != NULL);
        return socket_r;
    }
    assert(stdin_thread == NULL);

    do {
        // Prepare handles for thread
        tdata = (struct win_thread_data *)safe_zalloc(sizeof(struct win_thread_data));

        /* Create the listening socket for the thread. When it starts, it will
         * accept our connection and begin writing STDIN data to the connection. */
        tdata->socket_l = (int) inheritable_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (tdata->socket_l == -1)
        {
            //fprintf(stderr, "socket error: %d", socket_errno());
            break;
        }
        socksize = sizeof(selfaddr);
        memset(&selfaddr, 0, socksize);
        selfaddr.sin_family = AF_INET;
        selfaddr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
        // Bind to any available loopback port
        if (SOCKET_ERROR == bind(tdata->socket_l, (SOCKADDR*)&selfaddr, socksize))
        {
            //fprintf(stderr, "bind error: %d", socket_errno());
            break;
        }
        // Get the address that was assigned by bind()
        if (SOCKET_ERROR == getsockname(tdata->socket_l, (SOCKADDR*)&selfaddr, &socksize))
        {
            //fprintf(stderr, "getsockname error: %d", socket_errno());
            break;
        }
        if (SOCKET_ERROR == listen(tdata->socket_l, 1))
        {
            //fprintf(stderr, "listen error: %d\n", socket_errno());
            break;
        }

        /* Make a copy of the stdin handle to be used by win_stdin_thread_func.  It
           will remain a reference to the true stdin after we fake stdin to read
           from the socket instead. */
        if (DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_INPUT_HANDLE),GetCurrentProcess(), &tdata->stdin_handle,0, FALSE, DUPLICATE_SAME_ACCESS) == 0)
        {
            //fprintf(stderr, "DuplicateHandle error: %08x", GetLastError());
            break;
        }

        /* Start up the thread. We don't bother keeping a reference to it
           because it runs until program termination. From here on out all reads
           from the stdin handle or file descriptor 0 will be reading from the
           socket that is fed by the thread. */
        stdin_thread = CreateThread(NULL, 0, win_stdin_thread_func, tdata, 0, NULL);

        if (stdin_thread == NULL)
        {
            //fprintf(stderr, "CreateThread error: %08x", GetLastError());
            break;
        }

        // Connect to the thread and rearrange our own STDIN handles
        // Sockets are created with WSA_FLAG_OVERLAPPED, which is needed for socket functions,
        // but it means we can't use read().
        socket_r = (int)inheritable_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (socket_r == INVALID_SOCKET)
        {
            //fprintf(stderr, "socket error: %d", socket_errno());
            break;
        }
        if (SOCKET_ERROR == connect(socket_r, (SOCKADDR*)&selfaddr, socksize))
        {
            //fprintf(stderr, "connect error: %d", socket_errno());
            break;
        }

        /* Set the stdin handle to read from the socket. */
        if (SetStdHandle(STD_INPUT_HANDLE, (HANDLE) socket_r) == 0)
        {
            //fprintf(stderr, "SetStdHandle error: %08x", GetLastError());
            break;
        }
        /* Need to redirect file descriptor 0 also. _open_osfhandle makes a new file
           descriptor from an existing handle. */
        /* Remember the newline translation mode (_O_TEXT or _O_BINARY), and
           restore it in the new file descriptor. */
        stdin_fmode = _getmode(STDIN_FILENO);
        stdin_fd = _open_osfhandle((intptr_t) GetStdHandle(STD_INPUT_HANDLE), _O_RDONLY | stdin_fmode);

        if (stdin_fd == -1)
        {
            break;
        }
        if (dup2(stdin_fd, STDIN_FILENO) != 0)
        {
            break;
        }
        rc = 1;
    } while (0);

    if (rc != 1)
    {
        if (socket_r != INVALID_SOCKET)
        {
            if (GetStdHandle(STD_INPUT_HANDLE) == (HANDLE) socket_r && tdata->stdin_handle)
            {
                // restore STDIN
                SetStdHandle(STD_INPUT_HANDLE, tdata->stdin_handle);
                tdata->stdin_handle = NULL; // make sure we don't close it later!
            }
            closesocket(socket_r);
            socket_r = INVALID_SOCKET;
        }
        if (stdin_thread)
        {
            TerminateThread(stdin_thread, 1);
            stdin_thread = NULL;
        }
        if (tdata)
        {
            if (tdata->stdin_handle)
            {
                CloseHandle(tdata->stdin_handle);
            }
            if (tdata->socket_l != INVALID_SOCKET)
            {
                closesocket(tdata->socket_l);
            }
            free(tdata);
        }
        return INVALID_SOCKET;
    }
    assert(socket_r != INVALID_SOCKET);
    return socket_r;
}





