package com.isteer.service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
@Service
public class JobTrackerService {
	private final ConcurrentMap<String, SseEmitter> emitters = new ConcurrentHashMap<>();

    public void register(String jobId, SseEmitter emitter) {
        emitters.put(jobId, emitter);
    }

    public SseEmitter get(String jobId) {
        return emitters.get(jobId);
    }

    public void complete(String jobId) {
        SseEmitter emitter = emitters.remove(jobId);
        if (emitter != null) {
            emitter.complete();
        }
    }
}
