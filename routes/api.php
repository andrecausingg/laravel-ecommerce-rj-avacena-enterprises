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

Route::middleware('jwt.verify')->prefix('signup')->group(function () {
    $SignUpController = AuthController::class;
    Route::post('/verify-email', [$SignUpController, 'verifyEmail']);
    Route::post('/resend-code', [$SignUpController, 'resendVerificationCode']);
});

Route::middleware(['jwt.auth'])->group(function () {
    $SignUpController = AuthController::class;
    Route::get('/index', [$SignUpController, 'index']);
});
