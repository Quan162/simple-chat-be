<?php

use App\Http\Controllers\AuthController;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware(['auth:sanctum', 'verified']);

Route::post('/auth/login', function (Request $request) {
    $validated = $request->validate([
        'email' => 'required|string|email|max:255',
        'password' => 'required|string|min:6',
    ]);
    if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
        $user = Auth::user();
        $token = $user->createToken("authToken")->plainTextToken;
        return response()->json(['token' => $token], 200);
    }
    return response()->json(['error' => 'Unauthorized'], 401);
})->middleware('verified');


Route::post('/auth/logout', function (Request $request) {
    $request->user()->tokens()->delete();
    return response()->json(['message' => 'Successfully logged out']);
})->middleware('auth:sanctum');

Route::post('/auth/register', [AuthController::class, 'register']);
Route::post('/auth/verify_code', [AuthController::class, 'verify_code']);
