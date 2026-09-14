package com.example.apisecurity.ch3;

/** The book's "Recipe API" example from Chapter 3 (Cute-Cupcake Factory). */
public class Recipe {

    private String recipeId;
    private String name;
    private String ingredients;
    private String directions;

    public Recipe() {
    }

    public Recipe(String recipeId, String name, String ingredients, String directions) {
        this.recipeId = recipeId;
        this.name = name;
        this.ingredients = ingredients;
        this.directions = directions;
    }

    public String getRecipeId() {
        return recipeId;
    }

    public void setRecipeId(String recipeId) {
        this.recipeId = recipeId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIngredients() {
        return ingredients;
    }

    public void setIngredients(String ingredients) {
        this.ingredients = ingredients;
    }

    public String getDirections() {
        return directions;
    }

    public void setDirections(String directions) {
        this.directions = directions;
    }
}
