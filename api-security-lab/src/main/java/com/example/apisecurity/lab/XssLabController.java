package com.example.apisecurity.lab;

import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.Map;

/**
 * TRAINING LAB - Cross-Site Scripting (deliberately vulnerable).
 *
 * The rest of this project only returns JSON, so it has no HTML/XSS surface.
 * This lab renders HTML and shows BOTH a vulnerable and a safe variant of
 * reflected and stored XSS, so you can watch an injected <script>/<img onerror>
 * execute in a browser and then see output encoding neutralize it:
 *
 *   Reflected:
 *     GET  /api/lab/xss/reflect?msg=hi          -> VULNERABLE (raw echo)
 *     GET  /api/lab/xss/reflect-safe?msg=hi     -> SAFE (HTML-escaped)
 *   Stored:
 *     POST /api/lab/xss/comments {author,comment}
 *     GET  /api/lab/xss/comments/view           -> VULNERABLE (raw render)
 *     GET  /api/lab/xss/comments/view-safe      -> SAFE (HTML-escaped)
 *
 * Open the vulnerable URLs in a real browser (not just curl) to see the script
 * actually run. Payload to try:  <script>alert(document.domain)</script>
 * or  <img src=x onerror=alert(1)>
 *
 * !!! Local, controlled security training ONLY. Do not deploy publicly. !!!
 */
@RestController
@RequestMapping("/api/lab/xss")
public class XssLabController {

    private final JdbcTemplate jdbc;

    public XssLabController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // --- Reflected XSS --------------------------------------------------------

    /** VULNERABLE: the query parameter is written into the HTML response as-is. */
    @GetMapping(value = "/reflect", produces = MediaType.TEXT_HTML_VALUE)
    public String reflectVulnerable(@RequestParam(defaultValue = "hello") String msg) {
        return "<!doctype html><html><body>"
                + "<h1>Reflected XSS lab (VULNERABLE)</h1>"
                + "<p>You said: " + msg + "</p>"
                + "</body></html>";
    }

    /** SAFE: the same value, HTML-escaped, so markup is shown as text. */
    @GetMapping(value = "/reflect-safe", produces = MediaType.TEXT_HTML_VALUE)
    public String reflectSafe(@RequestParam(defaultValue = "hello") String msg) {
        return "<!doctype html><html><body>"
                + "<h1>Reflected XSS lab (SAFE)</h1>"
                + "<p>You said: " + HtmlUtils.htmlEscape(msg) + "</p>"
                + "</body></html>";
    }

    // --- Stored XSS -----------------------------------------------------------

    public record Comment(String author, String comment) {
    }

    /** Store a comment (its content is rendered later by the two view endpoints). */
    @PostMapping("/comments")
    public Map<String, Object> addComment(@RequestBody Comment c) {
        jdbc.update("INSERT INTO lab_comments (author, comment) VALUES (?, ?)",
                c.author(), c.comment());
        return Map.of("stored", true,
                "hint", "Now open /api/lab/xss/comments/view (vulnerable) vs "
                        + "/api/lab/xss/comments/view-safe in a browser.");
    }

    /** VULNERABLE: stored comments are rendered into HTML without encoding. */
    @GetMapping(value = "/comments/view", produces = MediaType.TEXT_HTML_VALUE)
    public String viewVulnerable() {
        StringBuilder sb = new StringBuilder("<!doctype html><html><body>"
                + "<h1>Stored XSS lab (VULNERABLE)</h1>");
        for (Map<String, Object> row : jdbc.queryForList("SELECT author, comment FROM lab_comments ORDER BY id")) {
            sb.append("<div><b>").append(row.get("author")).append("</b>: ")
                    .append(row.get("comment")).append("</div>");
        }
        return sb.append("</body></html>").toString();
    }

    /** SAFE: stored comments are HTML-escaped on the way out. */
    @GetMapping(value = "/comments/view-safe", produces = MediaType.TEXT_HTML_VALUE)
    public String viewSafe() {
        StringBuilder sb = new StringBuilder("<!doctype html><html><body>"
                + "<h1>Stored XSS lab (SAFE)</h1>");
        for (Map<String, Object> row : jdbc.queryForList("SELECT author, comment FROM lab_comments ORDER BY id")) {
            sb.append("<div><b>").append(HtmlUtils.htmlEscape(String.valueOf(row.get("author")))).append("</b>: ")
                    .append(HtmlUtils.htmlEscape(String.valueOf(row.get("comment")))).append("</div>");
        }
        return sb.append("</body></html>").toString();
    }
}
