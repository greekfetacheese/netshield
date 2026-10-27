/* click_at: synthetic click at window-relative coordinates, via XTest.
 *
 * Build: gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -lXtst
 *        (with only the libXtst runtime installed, and no -dev symlink:
 *         gcc -O2 -o target/dev/click_at dev/click_at.c -lX11 -Wl,-l:libXtst.so.6)
 * Run:   target/dev/click_at WINDOW_ID REL_X REL_Y
 *
 * The delays are load-bearing: egui drops a press+release delivered with zero delay, and
 * the motion must settle before the button events.  The first click on an unfocused window
 * is eaten by focus-follows, so click twice (or focus the window first).
 *
 * Links against libXtst.so.6 directly because the -dev headers are not installed; the two
 * XTest entry points below are the ABI the library exports. */
#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int XTestFakeMotionEvent(Display *dpy, int screen, int x, int y,
                                unsigned long delay);
extern int XTestFakeButtonEvent(Display *dpy, unsigned int button, int is_press,
                                unsigned long delay);

static void usage(FILE *out) {
    fprintf(out,
            "usage: click_at WINDOW_ID REL_X REL_Y\n"
            "\n"
            "Clicks button 1 at (REL_X, REL_Y), relative to the top-left of WINDOW_ID,\n"
            "by translating to root coordinates and injecting XTest events.  The delays\n"
            "around motion and press/release are required: egui drops a zero-delay click.\n"
            "\n"
            "The first click on an unfocused window is taken by the focus-follows window\n"
            "manager; run it twice if the first one does nothing.\n"
            "\n"
            "Exit codes: 0 success, 2 bad usage, 3 cannot open the display.\n");
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(stdout);
        return 0;
    }
    if (argc != 4) {
        usage(stderr);
        return 2;
    }
    Display *d = XOpenDisplay(NULL);
    if (!d) {
        fprintf(stderr, "click_at: cannot open the X display (is DISPLAY set?)\n");
        return 3;
    }
    Window w = (Window)strtoul(argv[1], NULL, 0);
    int rx = atoi(argv[2]), ry = atoi(argv[3]);
    int wx = 0, wy = 0;
    Window child;
    XTranslateCoordinates(d, w, DefaultRootWindow(d), rx, ry, &wx, &wy, &child);
    XTestFakeMotionEvent(d, -1, wx, wy, 0);
    XFlush(d);
    usleep(250000);
    XTestFakeMotionEvent(d, -1, wx, wy, 0);
    XFlush(d);
    usleep(150000);
    XTestFakeButtonEvent(d, 1, True, 0);
    XFlush(d);
    usleep(150000);
    XTestFakeButtonEvent(d, 1, False, 0);
    XFlush(d);
    usleep(100000);
    XCloseDisplay(d);
    return 0;
}
