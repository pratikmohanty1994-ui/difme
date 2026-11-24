package dev.difme.railsworker;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** A set of Fluxnova external-task topics and how to answer them. */
interface Tasks {
    List<String> topics();

    /** The variables to complete the task with; a RuntimeException is a failure, retried by Fluxnova. */
    Map<String, Object> handle(Fluxnova.Task t);

    /** Several sets as one (each topic answered by the set that lists it). */
    static Tasks of(Tasks... sets) {
        List<String> all = new ArrayList<>();
        for (Tasks s : sets) all.addAll(s.topics());
        return new Tasks() {
            public List<String> topics() { return all; }
            public Map<String, Object> handle(Fluxnova.Task t) {
                for (Tasks s : sets) if (s.topics().contains(t.topic())) return s.handle(t);
                throw new IllegalArgumentException("unknown topic " + t.topic());
            }
        };
    }
}
