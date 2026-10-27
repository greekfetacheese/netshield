/* iconify: iconify a window with XIconifyWindow.
 *
 * Build: gcc -O2 -o target/dev/iconify dev/iconify.c -lX11
 * Run:   target/dev/iconify WINDOW_ID
 *
 * `wmctrl -b add,hidden` does not reliably iconify under Muffin; XIconifyWindow sends the
 * request the window manager actually honours, so the window ends up `Iconic` in
 * `xprop -id ID WM_STATE`.  Needs a real X display and the X11 development headers. */
#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
    fprintf(out,
            "usage: iconify WINDOW_ID\n"
            "\n"
            "Iconifies WINDOW_ID via XIconifyWindow.  WINDOW_ID is the hex id from\n"
            "`wmctrl -lG` or `xwininfo -root -tree` (for example 0x2400003).\n"
            "\n"
            "Succeeds when `xprop -id WINDOW_ID WM_STATE` then reports Iconic.\n"
            "Exit codes: 0 success, 2 bad usage, 3 cannot open the display.\n");
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc != 2) {
        usage(stderr);
        return 2;
    }
    Display *d = XOpenDisplay(NULL);
    if (!d) {
        fprintf(stderr, "iconify: cannot open the X display (is DISPLAY set?)\n");
        return 3;
    }
    Window w = (Window)strtoul(argv[1], NULL, 0);
    XIconifyWindow(d, w, DefaultScreen(d));
    XFlush(d);
    XCloseDisplay(d);
    return 0;
}
