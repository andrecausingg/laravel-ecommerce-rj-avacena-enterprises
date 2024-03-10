<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserInfoController;
use App\Http\Controllers\InventoryController;
use App\Http\Controllers\InventoryProductController;

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

Route::get('/index-history', [AuthController::class, 'indexHistory']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);
Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);

// Authenticated Users
Route::middleware(['jwt.auth'])->group(function () {
    $AuthController = AuthController::class;
    $UserInfoController = UserInfoController::class;
    $InventoryController = InventoryController::class;
    $InventoryProductController = InventoryProductController::class;

    // Register
    Route::prefix('signup')->group(function () use ($AuthController) {
        Route::post('/verify-email', [$AuthController, 'verifyEmail']);
        Route::post('/resend-code', [$AuthController, 'resendVerificationCode']);
    });

    // User Accounts
    Route::prefix('accounts')->group(function () use ($AuthController) {
        Route::get('/index', [$AuthController, 'index']);
        Route::patch('/update-email', [$AuthController, 'updateEmailAdmin']);
        Route::patch('/update-password', [$AuthController, 'updatePasswordAdmin']);
        Route::patch('/update-role-status', [$AuthController, 'updateRoleAndStatus']);
    });

    // Update Password
    Route::prefix('new-password')->group(function () use ($AuthController) {
        Route::post('/update-password', [$AuthController, 'updatePassword']);
    });

    // Personal User Information
    Route::prefix('user-info')->group(function () use ($UserInfoController, $AuthController) {
        Route::get('/index', [$UserInfoController, 'index']);
        Route::post('/store', [$UserInfoController, 'store']);
        Route::patch('/update', [$UserInfoController, 'update']);
        Route::get('/get-personal-info', [$UserInfoController, 'getPersonalInfo']);

        Route::patch('/update-password', [$AuthController, 'updatePasswordOnSettingUser']);
        Route::patch('/update-email', [$AuthController, 'updateEmailOnSettingUser']);
        Route::patch('/update-password/send-verification-code', [$AuthController, 'updateEmailAndPasswordSendVerificationCode']);
    });

    // Inventory
    Route::prefix('inventory')->group(function () use ($InventoryController, $InventoryProductController) {
        Route::prefix('parent')->group(function () use ($InventoryController) {
            Route::get('index', [$InventoryController, 'index']);
            Route::post('store', [$InventoryController, 'store']);
            Route::get('edit/{id}', [$InventoryController, 'edit']);
            Route::patch('update', [$InventoryController, 'update']);
        });

        Route::prefix('product')->group(function () use ($InventoryProductController) {
            Route::post('/store', [$InventoryProductController, 'store']);
        });
    });
});
