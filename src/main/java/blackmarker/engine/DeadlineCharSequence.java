package blackmarker.engine;

/**
 * CharSequence wrapper that aborts a regex match once a deadline has passed.
 * HTTP content is untrusted and user-defined rules can be pathological, so a
 * runaway pattern must not be able to hang Burp's UI or traffic threads.
 *
 * Not thread-safe: create one per matching run.
 */
final class DeadlineCharSequence implements CharSequence {

    /** Thrown from {@link #charAt(int)} when the time budget is exhausted. */
    static final class RegexTimeoutException extends RuntimeException {
        RegexTimeoutException() {
            super("regex exceeded its time budget", null, false, false);
        }
    }

    private static final int CHECK_INTERVAL = 4096;

    private final CharSequence delegate;
    private final long deadlineNanos;
    private int calls;

    DeadlineCharSequence(CharSequence delegate, long budgetMillis) {
        this.delegate = delegate;
        this.deadlineNanos = System.nanoTime() + budgetMillis * 1_000_000L;
    }

    @Override
    public char charAt(int index) {
        if ((++calls & (CHECK_INTERVAL - 1)) == 0 && System.nanoTime() - deadlineNanos > 0) {
            throw new RegexTimeoutException();
        }
        return delegate.charAt(index);
    }

    @Override
    public int length() {
        return delegate.length();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new SubSequence(this, start, end);
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    /** Sub-sequence view that keeps routing reads through the deadline check. */
    private static final class SubSequence implements CharSequence {
        private final DeadlineCharSequence parent;
        private final int start;
        private final int end;

        SubSequence(DeadlineCharSequence parent, int start, int end) {
            this.parent = parent;
            this.start = start;
            this.end = end;
        }

        @Override public char charAt(int index) { return parent.charAt(start + index); }
        @Override public int length() { return end - start; }
        @Override public CharSequence subSequence(int s, int e) { return new SubSequence(parent, start + s, start + e); }
        @Override public String toString() { return parent.delegate.subSequence(start, end).toString(); }
    }
}
