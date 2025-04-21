package top.anyel.client.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

/*
 * Author: Anyel EC
 * Github: https://github.com/Anyel-ec
 * Creation date: 20/04/2025
 */
@RestController
public class ClientController {

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello");
    }

    @GetMapping("/authorized")
    public Map<String, String> authorize(@RequestParam String code) {
        return Collections.singletonMap("authorizationCode", code);
    }

}