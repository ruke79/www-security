package com.example.apisecurity.ch3;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

/**
 * Chapter 3 - HTTP Basic/Digest Authentication.
 *
 * The same in-memory "Recipe API" from the book, exposed twice:
 *   /api/ch3/basic/recipe/**   -> protected with HTTP Basic Authentication
 *   /api/ch3/digest/recipe/**  -> protected with a hand-rolled RFC 2617
 *                                 HTTP Digest Authentication filter
 *
 * ROLE_ADMIN can do GET/POST/PUT/DELETE, ROLE_USER can only GET - mirroring
 * the book's web.xml &lt;security-constraint&gt; example.
 *
 * Basic users:  admin/admin123 (ADMIN), alice/alice123 (USER)
 * Digest users: prabath/prabath123 (ADMIN), alice/alice123 (USER)
 */
@RestController
@RequestMapping({"/api/ch3/basic/recipe", "/api/ch3/digest/recipe"})
public class RecipeController {

    private final RecipeRepository repository;

    public RecipeController(RecipeRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    public Collection<Recipe> findAll() {
        return repository.findAll();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    public ResponseEntity<Recipe> findById(@PathVariable String id) {
        Recipe recipe = repository.findById(id);
        return recipe == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(recipe);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Recipe> create(@RequestBody Recipe recipe) {
        recipe.setRecipeId(null);
        Recipe saved = repository.save(recipe);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Recipe> update(@PathVariable String id, @RequestBody Recipe recipe) {
        if (repository.findById(id) == null) {
            return ResponseEntity.notFound().build();
        }
        recipe.setRecipeId(id);
        return ResponseEntity.ok(repository.save(recipe));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        repository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
