<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LogController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PaymentController;
use App\Http\Controllers\PurchaseController;
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
    $LogController = LogController::class;
    $PurchaseController = PurchaseController::class;
    $PaymentController = PaymentController::class;

    // Register
    Route::prefix('signup')->group(function () use ($AuthController) {
        Route::post('/verify-email', [$AuthController, 'verifyEmail']);
        Route::post('/resend-code', [$AuthController, 'resendVerificationAuth']);
    });

    // Update Password
    Route::prefix('new-password')->group(function () use ($AuthController) {
        Route::post('/update-password', [$AuthController, 'updatePassword']);
    });

    // User Accounts
    Route::prefix('accounts')->group(function () use ($AuthController) {
        Route::get('/index', [$AuthController, 'index']);
        Route::get('/show/{id}', [$AuthController, 'show']);
        Route::post('/update-email', [$AuthController, 'updateEmailAdmin']);
        Route::post('/update-password', [$AuthController, 'updatePasswordAdmin']);
        Route::post('/update-role-status', [$AuthController, 'updateRoleAndStatus']);
    });

    // Personal User Information
    Route::prefix('user-info')->group(function () use ($UserInfoController, $AuthController) {
        Route::get('/index', [$UserInfoController, 'index']);
        Route::post('/store', [$UserInfoController, 'store']);
        Route::post('/update', [$UserInfoController, 'update']);
        Route::get('/get-personal-info', [$UserInfoController, 'getPersonalInfo']);

        Route::post('/update-email', [$AuthController, 'updateEmailOnSettingUser']);
        Route::post('/update-password', [$AuthController, 'updatePasswordOnSettingUser']);
        Route::post('/update-password-and-email/send-verification-code', [$AuthController, 'updateEmailAndPasswordSendVerificationCode']);
    });

    // Inventory
    Route::prefix('inventory')->group(function () use ($InventoryController, $InventoryProductController) {
        Route::prefix('parent')->group(function () use ($InventoryController) {
            Route::get('index', [$InventoryController, 'index']);
            Route::post('store', [$InventoryController, 'store']);
            Route::get('edit/{id}', [$InventoryController, 'edit']);
            Route::post('update', [$InventoryController, 'update']);
        });

        Route::prefix('product')->group(function () use ($InventoryProductController) {
            Route::get('/index', [$InventoryProductController, 'index']);
            Route::post('/store', [$InventoryProductController, 'store']);
            Route::post('/update', [$InventoryProductController, 'update']);
        });
    });

    // Purchase
    Route::prefix('purchase')->group(function () use ($PurchaseController) {
        Route::get('/get-user-id-menu-costumer', [$PurchaseController, 'getUserIdMenuCustomer']);
        Route::post('/store', [$PurchaseController, 'store']);
        Route::post('/minus-qty', [$PurchaseController, 'minusQty']);
        Route::post('/add-qty', [$PurchaseController, 'addQty']);
        Route::post('/delete-all-qty', [$PurchaseController, 'deleteAll']);
    });

    // Payment
    Route::prefix('payment')->group(function () use ($PaymentController) {
        Route::post('/payment', [$PaymentController, 'payment']);
    });

    Route::prefix('log')->group(function () use ($LogController) {
        Route::get('index', [$LogController, 'index']);
    });
});
