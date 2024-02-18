<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });


Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);

// Register and Update New Password
Route::middleware('jwt.verify')->group(function () {
    $AuthController = AuthController::class;

    Route::prefix('signup')->group(function () use ($AuthController) {
        Route::post('/verify-email', [$AuthController, 'verifyEmail']);
        Route::post('/resend-code', [$AuthController, 'resendVerificationCode']);
    });

    Route::prefix('new-password')->group(function () use ($AuthController) {
        Route::post('/update-password', [$AuthController, 'updatePassword']);
    });

});

// Authenticated Users
Route::middleware(['jwt.auth'])->group(function () {
    $AuthController = AuthController::class;
    Route::get('/index', [$AuthController, 'index']);
});