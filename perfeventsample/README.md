# Listening to perf events


This is a poor man's version of how pyroscope works.

We listen to perf_events, store the occurrences of any given stack in a map,
then retrieve the stack with the highest number of occurrences.
