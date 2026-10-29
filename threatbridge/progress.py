"""Progress of long jobs, such as building a case: one updating line on a terminal, otherwise a
log line every `interval` seconds and when each stage ends."""
import logging
import os
import sys
import time
from contextlib import contextmanager

log = logging.getLogger("threatbridge")


class Progress:
    def __init__(self, stream=None, interval=10.0, clock=time.monotonic):
        self.stream = sys.stderr if stream is None else stream
        try:
            self.tty = self.stream.isatty()
        except (AttributeError, ValueError):   # no isatty, or a closed stream
            self.tty = False
        self.interval, self.clock = interval, clock

    def columns(self):
        """The terminal's width now (it may have been resized); 80 when it can't tell."""
        try:
            return os.get_terminal_size(self.stream.fileno()).columns or 80
        except (AttributeError, OSError, ValueError):
            return 80

    @contextmanager
    def stage(self, name, total=None):
        """A step of the job. Call the stage with the amount done since the last call (bytes,
        flows, ...) and, optionally, a note such as "file 3 of 12"."""
        stage = Stage(self, name, total)
        yield stage
        stage.end()


class Stage:
    def __init__(self, progress, name, total):
        self.progress, self.name, self.total = progress, name, total
        self.done, self.note = 0, ""
        self.start = self.shown = progress.clock()
        self.width = 0
        if progress.tty:
            # A log line written while the progress line is up starts on a clean line.
            self.clear_first = lambda record: self.clear() or True
            for handler in logging.getLogger().handlers:
                handler.addFilter(self.clear_first)
            self._write(f"{name}…")

    def __call__(self, amount=0, note=None):
        self.done += amount
        if note is not None:
            self.note = note
        now = self.progress.clock()
        if now - self.shown >= (0.25 if self.progress.tty else self.progress.interval):
            self.shown = now
            text = self.describe(now)
            if self.progress.tty:
                self._write(text)
            else:
                log.info("%s", text)

    def describe(self, now):
        """E.g. "Reading evidence: 41%, file 3 of 12, 1,204,332 packets, about 1 min 10 s left"."""
        parts = []
        if self.total:
            parts.append(f"{min(100, int(100 * self.done / self.total))}%")
        if self.note:
            parts.append(self.note)
        elapsed = now - self.start
        if self.total and self.done and elapsed >= 2:
            parts.append(f"about {_duration(elapsed * (self.total - self.done) / self.done)} left")
        return f"{self.name}: " + ", ".join(parts) if parts else f"{self.name}…"

    def end(self):
        took = self.progress.clock() - self.start
        text = f"{self.name}: done in {_duration(took)}" + (f" ({self.note})" if self.note else "")
        if self.progress.tty:
            for handler in logging.getLogger().handlers:
                handler.removeFilter(self.clear_first)
            self._write(text, fit=False)          # kept whole: a new line follows it
            self.progress.stream.write("\n")
            self.progress.stream.flush()
        else:
            log.info("%s", text)

    def _write(self, text, fit=True):
        # A line that wraps can't be redrawn: "\r" goes back to the start of its last row only.
        columns = self.progress.columns()
        if fit and len(text) >= columns:
            text = text[:max(0, columns - 2)] + "…"
        self.progress.stream.write("\r" + text.ljust(min(self.width, columns - 1)))
        self.progress.stream.flush()
        self.width = len(text)

    def clear(self):
        if self.width:
            self.progress.stream.write("\r" + " " * min(self.width, self.progress.columns() - 1) + "\r")
            self.progress.stream.flush()
            self.width = 0


class _Quiet:
    """Progress that shows nothing."""

    @contextmanager
    def stage(self, name, total=None):
        yield lambda amount=0, note=None: None


QUIET = _Quiet()


def counted(rows, stage, every=50_000):
    """`rows`, unchanged, telling `stage` about every `every` of them as they go by."""
    n = 0
    for row in rows:
        yield row
        n += 1
        if n == every:
            stage(n)
            n = 0
    stage(n)


def _duration(seconds):
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s"
    return f"{minutes // 60} h {minutes % 60} min"
