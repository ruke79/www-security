package com.example.apisecurity.lab;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TRAINING LAB - Server-Side Template Injection / expression injection, shown
 * with Spring's own SpEL (Spring Expression Language). Deliberately vulnerable;
 * local training only.
 *
 * SSTI happens when user input is evaluated as a template/expression on the
 * server. In the Spring world the canonical form is SpEL evaluated with a full
 * StandardEvaluationContext - which exposes type references and method calls,
 * leading to remote code execution.
 *
 *   GET /api/lab/ssti/greet?name=World                 -> VULNERABLE (SpEL eval)
 *   GET /api/lab/ssti/greet-safe?name=World            -> SAFE (no eval / restricted)
 *
 * Try (URL-encode as needed):
 *   ?name=${7*7}  is NOT how SpEL works; SpEL is evaluated directly, e.g.:
 *   ?name=T(java.lang.Runtime).getRuntime().exec('id')          (object -> RCE)
 *   ?name=T(java.lang.System).getProperty('user.name')          (read a property)
 *   ?name=new java.lang.ProcessBuilder('id').start()            (RCE)
 */
@RestController
@RequestMapping("/api/lab/ssti")
public class SstiLabController {

    private final ExpressionParser parser = new SpelExpressionParser();

    /**
     * VULNERABLE: the {@code name} parameter is parsed and evaluated as a SpEL
     * expression against a StandardEvaluationContext, which allows type
     * references (T(...)), constructors and arbitrary method calls -> RCE.
     */
    @GetMapping("/greet")
    public ResponseEntity<Object> greetVulnerable(@RequestParam String name) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "VULNERABLE (SpEL evaluated with StandardEvaluationContext)");
        out.put("input", name);
        try {
            EvaluationContext ctx = new StandardEvaluationContext();
            Expression expr = parser.parseExpression(name);
            Object value = expr.getValue(ctx);
            out.put("evaluatedResult", String.valueOf(value));
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return ResponseEntity.ok(out);
    }

    /**
     * SAFE: two independent defenses.
     *  1) The template is a fixed server-side string; user input is inserted as
     *     DATA (a variable), never parsed as part of the expression.
     *  2) Even that data-only evaluation uses a SimpleEvaluationContext, which
     *     forbids type references, constructors and arbitrary method calls.
     */
    @GetMapping("/greet-safe")
    public ResponseEntity<Object> greetSafe(@RequestParam String name) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "SAFE (fixed template + SimpleEvaluationContext; input is data, not code)");
        out.put("input", name);
        // Input is bound as a variable and only read back - never parsed as SpEL.
        EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        ctx.setVariable("name", name);
        Expression template = parser.parseExpression("'Hello, ' + #name + '!'");
        out.put("evaluatedResult", String.valueOf(template.getValue(ctx)));
        return ResponseEntity.ok(out);
    }
}
