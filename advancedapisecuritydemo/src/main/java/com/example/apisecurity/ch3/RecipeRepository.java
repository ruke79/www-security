package com.example.apisecurity.ch3;

import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Repository
public class RecipeRepository {

    private final Map<String, Recipe> recipes = new ConcurrentHashMap<>();
    private final AtomicInteger sequence = new AtomicInteger(10000);

    public RecipeRepository() {
        save(new Recipe(null, "Lemon Cupcake",
                "lemon zest, white sugar, unsalted butter, flour, salt, milk",
                "Preheat oven to 375F (190C). Line cupcake pan with paper liners..."));
        save(new Recipe(null, "Red Velvet Cupcake",
                "cocoa powder, eggs, white sugar, unsalted butter, flour, salt",
                "Preheat oven to 350F (175C). Mix flour, cocoa powder, baking soda and salt..."));
    }

    public Collection<Recipe> findAll() {
        return recipes.values();
    }

    public Recipe findById(String id) {
        return recipes.get(id);
    }

    public Recipe save(Recipe recipe) {
        if (recipe.getRecipeId() == null) {
            recipe.setRecipeId(String.valueOf(sequence.incrementAndGet()));
        }
        recipes.put(recipe.getRecipeId(), recipe);
        return recipe;
    }

    public void deleteById(String id) {
        recipes.remove(id);
    }
}
