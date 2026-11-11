package r5gk.boot;

/** Receives one line of progress output from the bring-up engine. */
@FunctionalInterface
interface LogSink {
    void line(String s);
}
