package com.isteer.cvssanalyzer.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.exception.NvdApiException;
import com.isteer.cvssanalyser.core.logging.Slf4jEngineLogger;
import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
    private CvssService service;

    public CvssController(CvssService cvssService) {
        this.service = cvssService;
    }

    @GetMapping("/getVulnerabilities")
    public SseEmitter getVulnerabilities() {
        SseEmitter emitter = new SseEmitter(0L);
        new Thread(() -> {
            try {
                Engine.withLogger(new Slf4jEngineLogger());
                Engine.analyze(EngineMode.POM, emitter);
                Engine.doFuzzySearchAndGetLikelyCpes();
                emitter.send(SseEmitter.event().data("Analysis completed"));
            } catch (Exception e) {
                emitter.completeWithError(e);
            } finally {
                emitter.complete();
            }
        }).start();
        return emitter;
    }

    @GetMapping("/vulnerabilities")
    public ResponseEntity<Object> getAllVulnerabilities() {
        return ResponseEntity.ok(Engine.dependencies);
    }

    @GetMapping("/search/cve/cveId")
    public ResponseEntity<Object> getVulnerabilitiesByCveId(@RequestParam String cveId) {
        try {
            Object result = service.getVulnerabilitiesByCveId(cveId);
            return ResponseEntity.ok(result);
        } catch (NvdApiException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        }
    }

    @GetMapping("/search/cve/keywords")
    public ResponseEntity<Object> getVulnerabilitiesByKeywords(@RequestParam String keywords) {
        try {
            Object result = service.getVulnerabilitiesByKeywords(keywords);
            return ResponseEntity.ok(result);
        } catch (NvdApiException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        }
    }

    @GetMapping("/search/cve/cpeName")
    public ResponseEntity<Object> getVulnerabilitiesByCpe(@RequestParam String cpe) {
        try {
            Object result = service.getVulnerabilitiesByCpe(cpe);
            return ResponseEntity.ok(result);
        } catch (NvdApiException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        }
    }

    @GetMapping("/search/cpe/matchingCpeName")
    public ResponseEntity<Object> getCpeNameList(@RequestParam String cpeName) {
        try {
            Object result = service.getCpeNameList(cpeName);
            return ResponseEntity.ok(result);
        } catch (NvdApiException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        }
    }

    @GetMapping("/search/cpe/keyword")
    public ResponseEntity<Object> getCpeNameListByKeyword(@RequestParam String keyword) {
        try {
            Object result = service.getCpeNameListByKeywords(keyword);
            return ResponseEntity.ok(result);
        } catch (NvdApiException ex) {
            return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
        }
    }
}
