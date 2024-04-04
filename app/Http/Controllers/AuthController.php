<?php

namespace App\Http\Controllers;

use App\Models\AuthModel;
use App\Models\LogsModel;
use Illuminate\Support\Str;
use App\Models\HistoryModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use App\Mail\VerificationMail;
use Illuminate\Support\Carbon;
use App\Mail\ResetPasswordMail;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;
use App\Mail\ResendVerificationMail;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function indexHistory()
    {
        $decryptedData = [];

        $historys = HistoryModel::get();

        foreach ($historys as $history) {
            $decryptedHistory = [
                'history_id' => $history && $history->history_id ? $history->history_id : null,
                'tbl_id' => $history && $history->tbl_id ? $history->tbl_id : null,
                'table_name' => $history && $history->tbl_name ? $history->tbl_name : null,
                'column_name' => $history && $history->column_name ? $history->column_name : null,
                'value' => $history && $history->value ? Crypt::decrypt($history->value) : null,
            ];

            $decryptedData[] = $decryptedHistory;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decryptedData,
            ],
            Response::HTTP_OK
        );
    }

    public function login(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);
        $clientRole = env('ROLE_CLIENT');
        $adminRole = env('ROLE_ADMIN');
        $delivery = env('ROLE_DELIVERY');
        $cashier = env('ROLE_CASHIER');

        // Validation rules
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Decrypt al email first
        $users = AuthModel::all();

        foreach ($users as $user) {
            $decryptedEmail = Crypt::decrypt($user->email);

            // Check if Verified Email
            if ($decryptedEmail == $request->input('email') && Hash::check($request->input('password'), $user->password) && $user->email_verified_at !== null) {
                // $expirationTime = Carbon::now()->addSeconds(30);
                // Expiration Time 1month
                $expirationTime = Carbon::now()->addMinutes(2592000);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);
                if (!$newToken) {
                    return response()->json([
                        'message' => 'Unable to generate a token from user'
                    ], Response::HTTP_OK);
                }

                $user->session_token = $newToken;
                $user->session_expire_at = $expirationTime;

                if ($user->save()) {
                    // Check If users_info_tbl exist 
                    $userInfoExists = UserInfoModel::where('user_id', $user->user_id)
                        ->where(function ($query) {
                            $query->whereNull('first_name')->orWhere('first_name', '');
                            $query->orWhereNull('last_name')->orWhere('last_name', '');
                        })
                        ->exists();

                    // Logs
                    $this->loginLogs($request, $user->user_id);

                    return response()->json([
                        'role' => $user->role === $clientRole ? $clientRole : ($user->role === $adminRole ? $adminRole : ($user->role === $delivery ? $delivery : ($user->role === $cashier ? $cashier : ''))),
                        // 'user' => $user,
                        'user_info' => $userInfoExists ? 'Existing User' : 'New User',
                        'token_type' => 'Bearer',
                        'access_token' => $newToken,
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                        'message' => 'Login Successfully'
                    ], Response::HTTP_OK);
                }

                return response()->json(
                    ['message' => 'Failed to update session token and expiration'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }
            // Check if Not Verified then redirect to Verify Email
            else if ($decryptedEmail == $request->input('email') && Hash::check($request->input('password'), $user->password) && $user->email_verified_at === null) {
                // Generate a new token for the user
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

                if (!$newToken) {
                    return response()->json([
                        'message' => 'Failed to generate a token from user'
                    ], Response::HTTP_OK);
                }

                // Update verification_number | password | verify email token
                $user->verification_number = $verificationNumber;
                $user->verify_email_token = $newToken;
                $user->verify_email_token_expire_at = $expirationTime;

                // Save
                if (!$user->save()) {
                    return response()->json(
                        [
                            'message' => 'Failed To update to verification number, token and expiration time'
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }
                // Get the Name of Gmail
                $emailParts = explode('@', $decryptedEmail);
                $name = [$emailParts[0]];

                // Send the new token to the user via email
                Mail::to($decryptedEmail)->send(new VerificationMail($verificationNumber, $name));

                return response()->json(
                    [
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                        'message' => '/signup/verify-email?tj=' . $newToken,
                    ],
                    Response::HTTP_OK
                );
            }
        }

        return response()->json([
            'message' => 'Invalid credential'
        ], Response::HTTP_OK);
    }

    // PARENT REGISTER
    public function register(Request $request)
    {
        // Declare Value
        $verificationNumber = mt_rand(100000, 999999);
        $accountRole = env('ROLE_CLIENT');
        $status = 'PENDING';
        do {
            $userId = Str::uuid()->toString();
        } while (AuthModel::where('user_id', $userId)->exists());

        // Check if phone number is not empty
        if (($request->input('phone_number') !== '' || $request->input('phone_number') !== null) && ($request->input('email') === '' || $request->input('email') === null)) {
            $validator = Validator::make($request->all(), [
                'phone_number' => 'required|numeric',
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()],  Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }
        // Check if Email is not empty
        else if ($request->input('email') !== '' || $request->input('email') !== null && ($request->input('phone_number') === '' || $request->input('phone_number') === null)) {
            // Validate Password
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
            }

            return $this->emailRegister($request, $userId, $verificationNumber, $accountRole, $status, $request->input('email'), $request->input('password'));
        } else {
            return response()->json(['message' => 'Please Input on Phone Number or Email', Response::HTTP_UNPROCESSABLE_ENTITY], 0);
        }
    }

    // CHILD REGISTER EMAIL
    public function emailRegister($request, $userId, $verificationNumber, $accountRole, $status, $email, $password)
    {
        // Get All Users and Decrypt
        $users = AuthModel::all();

        // Decrypt
        foreach ($users as $user) {
            // Start Decrypt
            $decryptedEmail = Crypt::decrypt($user->email);

            // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
            if ($decryptedEmail === $email && $user->email_verified_at === null) {
                // Generate a new token for the user
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

                if (!$newToken) {
                    return response()->json([
                        'message' => 'Unable to generate a token from user'
                    ], Response::HTTP_OK);
                }

                // Update verification_number | password | verify email token
                $user->verification_number = $verificationNumber;
                $user->password = Hash::make($password);
                $user->verify_email_token = $newToken;
                $user->verify_email_token_expire_at = $expirationTime;

                // Save
                if ($user->save()) {
                    // Indicator Logs
                    $indicator = 'existAccCreate';

                    // Array Logs
                    $logsData = [
                        'user_id' => $user->user_id,
                        'fields' => [
                            'email' => Crypt::encrypt($email),
                            'password' => Crypt::encrypt($password),
                        ]
                    ];

                    // Logs
                    $logResult = $this->emailRegisterLogs($request, $userId, $indicator, $logsData);


                    // Get the Name of Gmail
                    $emailParts = explode('@', $email);
                    $name = [$emailParts[0]];

                    // Send the new token to the user via email
                    $email = Mail::to($email)->send(new VerificationMail($verificationNumber, $name));
                    if (!$email) {
                        return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                    }
                    return response()->json(
                        [
                            'message' => 'Successfully create token',
                            // 'data' => $user,
                            'url_token' => '/signup/verify-email?tj=' . $newToken,
                            'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                            'log_message' => $logResult
                        ],
                        Response::HTTP_OK
                    );
                }

                return response()->json(
                    [
                        'message' => 'Error updating verification number, token, and expiration time',
                    ],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // If same email exist and email_verified_at not null send error message
            else if ($decryptedEmail === $email && $user->email_verified_at !== null) {

                return response()->json(
                    [
                        'message' => 'Email already exist'
                    ],
                    Response::HTTP_UNPROCESSABLE_ENTITY
                );
            }
        }

        // User with the given email does not exist, create a new user
        $userCreate = AuthModel::create([
            'user_id' => $userId,
            'email' => Crypt::encrypt($email),
            'password' => Hash::make($password),
            'role' => $accountRole,
            'status' => $status,
            'verification_number' => $verificationNumber,
        ]);

        if (!$userCreate) {
            // Error creating user
            return response()->json(['message' => 'Failed to create user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Generate a new token for the user
        $expirationTime = Carbon::now()->addMinutes(120);
        $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($userCreate);

        if (!$newToken) {
            return response()->json(['message' => 'Failed to generate token'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Update user with the new token for email verification
        $userCreate->verify_email_token = $newToken;
        $userCreate->verify_email_token_expire_at = $expirationTime;

        if (!$userCreate->save()) {
            return response()->json(['message' => 'Failed to update token and expire at'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Indicator Logs
        $indicator = 'freshAccCreate';

        // Array Logs
        $logsData = [
            'user_id' => $userCreate->user_id,
            'fields' => [
                'email' => Crypt::encrypt($email),
                'password' => Crypt::encrypt($password),
            ]
        ];

        // Logs
        $logResult = $this->emailRegisterLogs($request, $userId, $indicator, $logsData);

        // Get the Name of Gmail
        $emailParts = explode('@', $email);
        $name = $emailParts[0];

        // Send an email to the user with the new token
        $email = Mail::to($email)->send(new VerificationMail($verificationNumber, $name));
        if (!$email) {
            return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json([
            'message' => 'Successfully create token',
            'url_token' => '/signup/verify-email?tj=' . $newToken,
            'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
            'log_message' => $logResult
        ], Response::HTTP_OK);
    }

    public function verifyEmail(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);
        $logDetails = [];

        // Authorize the user
        $user = $this->authorizeUserVerifyEmail($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate
        $validator = Validator::make($request->all(), [
            'verification_number' => 'required|numeric|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Check if the provided verification number matches the stored one
        if ($user->verification_number != $request->verification_number) {
            return response()->json(['message' => 'Invalid verification number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Expiration to verified Email
        $expirationTime = Carbon::now()->addSecond();
        $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

        // Update user status and set email_verified_at to the current timestamp
        $user->status = 'ACTIVE';
        $user->verify_email_token = $newToken;
        $user->email_verified_at = now();
        $user->verification_number = $verificationNumber;

        if ($user->save()) {
            $logDetails = [
                'user_id' => $user->user_id,
                'fields' => [
                    'status' => $user->status,
                    'verify_email_token' => $user->verify_email_token,
                    'email_verified_at' => $user->email_verified_at,
                    'verification_number' => $request->verification_number,
                ]
            ];
            $logResult = $this->verifyEmailLogs($request, $user->user_id, $logDetails);

            return response()->json(
                [
                    'message' => 'Email verified successfully',
                    'log_message' => $logResult
                ],
                Response::HTTP_OK
            );
        }
    }

    // SIGN UP | VERIFY EMAIL RESEND CODE
    public function resendVerificationAuth(Request $request)
    {
        $logDetails = [];
        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUserResendCode($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate 
        $validator = Validator::make($request->all(), [
            'indicator' => 'required|string|max:255',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }


        if ($request->indicator != env('VERIFY_EMAIL_NUM_CODE')) {
            return response()->json([
                'message' => 'Invalid indicator',
            ], Response::HTTP_UNAUTHORIZED);
        }

        if ($user->update([
            'verification_number' => $verificationNumber,
        ])) {
            $emailParts = explode('@', Crypt::decrypt($user->email));
            $name = [$emailParts[0]];

            if ($request->indicator == env('VERIFY_EMAIL_NUM_CODE')) {
                $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verificationNumber, $name));
                if (!$email) {
                    return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            $logDetails = [
                'user_id' => $user->user_id,
                'fields' => [
                    'verification_number' => $user->verification_number
                ]
            ];

            $logResult = $this->resendVerificationCodeAllLogs($request, $user->user_id, $request->indicator, $logDetails);

            return response()->json([
                'message' => 'A new verification code has been sent to your email',
                'log_message' => $logResult
            ], Response::HTTP_OK);
        }
    }

    public function forgotPassword(Request $request)
    {
        $logDetails = [];

        // Validate
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Get All Users and Decrypt
        $users = AuthModel::all();

        // Decrypt
        foreach ($users as $user) {
            // Start Decrypt
            $decryptedEmail = Crypt::decrypt($user->email);

            // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
            if ($decryptedEmail === $request->email && $user->email_verified_at !== null) {
                // 2hrs expiration to verified Email
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

                // Update token and expiration
                $user->reset_password_token = $newToken;
                $user->reset_password_token_expire_at = $expirationTime;

                // Save
                if (!$user->save()) {
                    return response()->json(['message' => 'Failed to save token and expiration',], Response::HTTP_INTERNAL_SERVER_ERROR);
                }

                // Send to Email Now
                $mail = Mail::to($request->email)->send(new ResetPasswordMail($newToken, $request->email, $expirationTime));
                if (!$mail) {
                    return response()->json(['message' => 'Failed to send reset password link on your email'], Response::HTTP_OK);
                }

                $logDetails = [
                    'user_id' => $user->user_id,
                    'fields' => [
                        'email' => Crypt::encrypt($request->email),
                    ]
                ];

                $logResult = $this->forgotPasswordLogs($request, $user->user_id, $logDetails);

                return response()->json([
                    'message' => 'Successfully sent a reset password link to your email ' . $decryptedEmail,
                    'log_message' => $logResult
                ], Response::HTTP_OK);
            }
            // If same email exist and email_verified_at equal null send error message
            else if ($decryptedEmail === $request->email && $user->email_verified_at === null) {
                return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
            }
        }

        return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
    }

    public function updatePassword(Request $request)
    {
        $logDetails = [];

        // Authorize the user
        $user = $this->authorizeUserUpdatePassword($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate Password
        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $user->user_id)->first();

        // Check if user exists
        if (!$userAuth) {
            return response()->json(['message' => 'Intruder'], Response::HTTP_NOT_FOUND);
        }

        if (Hash::check($request->input('password'), $userAuth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $history = HistoryModel::where('tbl_id', $userAuth->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
        $logDetails = [
            'user_id' => $user->user_id,
            'fields' => [
                'old_password' => $history->value,
                'new_password' => Crypt::encrypt($request->input('password')),
            ]
        ];

        // Expiration to verified Email
        $expirationTime = Carbon::now()->addSecond();
        $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

        // Update the user's password
        $userAuth->password =  Hash::make($request->input('password'));
        $userAuth->reset_password_token =  $newToken;
        $userAuth->reset_password_token_expire_at =  $expirationTime;

        // Saving
        if ($userAuth->save()) {
            // Logs
            $this->updatePasswordLogs($request, $user->user_id, $logDetails);

            return response()->json(['message' => 'Password updated successfully'], Response::HTTP_OK);
        } else {
            return response()->json(['message' => 'Failed to update new password'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // UPDATE PASSWORD | CLIENT SIDE
    public function updatePasswordOnSettingUser(Request $request)
    {
        $logDetails = [];

        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'password' => 'required|string|min:6|confirmed',
            'verification_number' => 'required|numeric|min:6',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $user->user_id)->first();

        // Check if user exists
        if (!$userAuth) {
            return response()->json(['message' => 'Intruder'], Response::HTTP_NOT_FOUND);
        }

        if (Hash::check($request->input('password'), $userAuth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (!Hash::check($request->input('current_password'), $userAuth->password)) {
            return response()->json(['message' => 'Incorrect current password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if ($userAuth->verification_number != $request->input('verification_number')) {
            return response()->json(['message' => 'Incorrect Verification Number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new passwords
            $logDetails = [
                'user_id' => $user->user_id,
                'fields' => [
                    'old_password' => Crypt::encrypt($request->input('current_password')),
                    'new_password' => Crypt::encrypt($request->input('password')),
                ]
            ];

            // Update the user's password
            $userAuth->password =  Hash::make($request->input('password'));
            $userAuth->verification_number = $verificationNumber;

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updatePasswordOnSettingUserLogs($request, $user->user_id, $logDetails);

                return response()->json(['message' => 'Password updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update new password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // UPDATE EMAIL | CLIENT SIDE
    public function updateEmailOnSettingUser(Request $request)
    {
        $logDetails = [];
        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'new_email' => 'required|email',
            'current_password' => 'required|string',
            'verification_number' => 'required|numeric|min:6',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $user->user_id)->first();
        // return response()->json(['message' => $userAuth], Response::HTTP_UNPROCESSABLE_ENTITY);

        if (Crypt::decrypt($userAuth->email) == $request->new_email) {
            return response()->json(['message' => 'The new email cannot be the same as the old email. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($userAuth->email) != $request->new_email && !Hash::check($request->input('current_password'), $userAuth->password)) {
            return response()->json(['message' => 'Incorrect password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($userAuth->email) != $request->new_email && Hash::check($request->input('current_password'), $userAuth->password) && $userAuth->verification_number != $request->verification_number) {
            return response()->json(['message' => 'Incorrect verification number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {

            $logDetails = [
                'user_id' => $user->user_id,
                'fields' => [
                    'old_email' => $userAuth->email,
                    'new_email' => Crypt::encrypt($request->new_email),
                ]
            ];

            // Update the user's email
            $userAuth->email = $logDetails['fields']['new_email'];
            $userAuth->verification_number = $verificationNumber;

            // Saving
            if ($userAuth->save()) {
                // Logs
                $logResult = $this->updateEmailOnSettingUserLogs($request, $user->user_id, $logDetails);

                return response()->json([
                    'message' => 'Email updated successfully',
                    'log_message' => $logResult,
                ], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // SEND VERIFICATION CODE | CLIENT SIDE
    public function updateEmailAndPasswordSendVerificationCode(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate 
        $validator = Validator::make($request->all(), [
            'indicator' => 'required|string|max:255',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        if ($request->indicator == env('UPDATE_EMAIL_NUM_CODE') && $request->indicator == env('UPDATE_PASSWORD_NUM_CODE')) {
            return response()->json([
                'message' => 'Invalid indicator',
            ], Response::HTTP_OK);
        }

        if ($user->update([
            'verification_number' => $verificationNumber,
        ])) {
            $emailParts = explode('@', Crypt::decrypt($user->email));
            $name = [$emailParts[0]];

            $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verificationNumber, $name));
            if (!$email) {
                return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $logDetails = [
                'user_id' => $user->user_id,
                'fields' => [
                    'verification_number' => $user->verification_number
                ]
            ];

            $logResult = $this->updateEmailAndPasswordSendVerificationCodeLogs($request, $user->user_id, $request->indicator, $logDetails);

            return response()->json([
                'message' => 'A new verification code has been sent to your email',
                'log_message' => $logResult
            ], Response::HTTP_OK);
        }
    }

    // GET ALL USER ACCOUNT | ADMIN SIDE
    public function index(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }
        // Decrypt all emails and other attributes
        $decryptedAuthUser = [];

        $authUsers = AuthModel::all();

        foreach ($authUsers as $authUser) {
            $decryptedEmail = $authUser->email ? Crypt::decrypt($authUser->email) : null;
            $userInfo = UserInfoModel::where('user_id', $authUser->user_id)->first(); // Assuming it returns one record
            $history = HistoryModel::where('tbl_id', $authUser->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();

            $decryptedAuthUser[] = [
                'id' => $authUser->id ?? null,
                'user_id' => $authUser->user_id ?? null,
                'password' => Crypt::decrypt($history->value) ?? null,
                'phone_number' => $authUser->phone_number ?? null,
                'email' => $decryptedEmail,
                'role' => $authUser->role ?? null,
                'status' => $authUser->status ?? null,
                'deleted_at' => $authUser->deleted_at ?? null,
                'created_at' => $authUser->created_at ?? null,
                'updated_at' => $authUser->updated_at ?? null,

                'userInfo' => [
                    'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                ],
            ];
        }

        // Display or use the decrypted attributes as needed
        return response()->json(['messages' => $decryptedAuthUser], Response::HTTP_OK);
    }

    // UPDATE EMAIL | ADMIN SIDE
    public function updateEmailAdmin(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        if ($user->user_id == '' || $user->user_id == null) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|string',
            'new_email' => 'required|email',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $request->user_id)->first();
        if (!$userAuth) {
            return response()->json(['message' => 'Data Not Found'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $isEmailsExist = AuthModel::get();
        $exist = 0;
        foreach ($isEmailsExist as $isEmailExist) {
            $decryptedEmail = Crypt::decrypt($isEmailExist->email) ?? null;
            if ($decryptedEmail == $request->new_email) {
                $exist = 1;
                break;
            }
        }

        $decryptedCurrentEmail = Crypt::decrypt($userAuth->email);
        if ($decryptedCurrentEmail == $request->new_email) {
            return response()->json(['message' => 'The new email cannot be the same as the old email. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if ($exist == 1) {
            return response()->json(['message' => 'The email is already taken'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new emails
            $logsData = [
                'old_email' => Crypt::encrypt($decryptedCurrentEmail),
                'new_email' => Crypt::encrypt($request->new_email),
            ];


            // Update the user's email
            $userAuth->email = $logsData['new_email'];

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updateEmailAdminLogs($request, $request->user_id, $user->user_id, $logsData);

                return response()->json(['message' => 'Email updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // UPDATE PASSWORD | ADMIN SIDE
    public function updatePasswordAdmin(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|string',
            'password' => 'required|string|min:6|confirmed:password_confirmation',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $request->user_id)->first();
        if (!$userAuth) {
            return response()->json(['message' => 'Data Not Found'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        if (Hash::check($request->new_password, $userAuth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new passwords
            $logsData = [
                'old_password' => $userAuth->password,
                'new_password' => Crypt::encrypt($request->input('password')),
            ];

            // Update the user password
            $userAuth->password = Hash::make($request->input('password'));

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updatePasswordAdminLogs($request, $request->user_id, $user->user_id, $logsData);

                return response()->json(['message' => 'Password updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // UPDATE ROLE AND STATUS | ADMIN SIDE
    public function updateRoleAndStatus(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);
        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|string',
            'role' => 'required|string|max:255',
            'status' => 'required|string|max:255',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', $request->user_id)->first();
        if (!$userAuth) {
            return response()->json(['message' => 'Data Not Found'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Define the fields to loop through
        $fields = [
            'role', 'status',
        ];

        $changesForLogs = [];

        // Loop through the fields for encryption and decryption
        foreach ($fields as $field) {
            try {
                // Check if the value has changed
                if ($request->input($field) !== $userAuth->$field) {
                    $changesForLogs[$field] = [
                        'old' => $userAuth->$field,
                        'new' => $request->input($field),
                    ];
                }

                // Update the user info
                $userAuth->$field = $request->input($field);
            } catch (\Exception $e) {
                // Log or dump information about the exception
                Log::info("Decryption error for field $field: " . $e->getMessage());
            }
        }

        // Save changes if any
        if (!empty($changesForLogs)) {
            if ($userAuth->save()) {
                // Logs
                $this->updateRoleAndStatusLogs($request, $request->user_id, $user->user_id, $changesForLogs);

                return response()->json(['message' => 'Role and Status updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update Role and Status'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        } else {
            return response()->json(['message' => 'No changes to update'], Response::HTTP_OK);
        }
    }

    // Authenticate Token
    public function authorizeUser($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();
            if (!$bearerToken || $user->session_token !== $bearerToken || $user->session_expire_at < Carbon::now()) {
                return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function authorizeUserVerifyEmail($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();
            if (!$bearerToken || $user->verify_email_token !== $bearerToken || $user->verify_email_token_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // This resend code for sign up verify email only
    public function authorizeUserResendCode($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();

            if (!$bearerToken || $user->verify_email_token !== $bearerToken || $user->verify_email_token_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // This resend code for update password and update email on user settings
    public function authorizeUserResendCodeUpdatePasswordAndUpdateEmailOnUserSetting($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();

            if (!$bearerToken || $user->session_token !== $bearerToken || $user->session_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function authorizeUserUpdatePassword($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();

            if (!$bearerToken || $user->reset_password_token !== $bearerToken || $user->reset_password_token_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            return $user;
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['error' => 'Failed to authenticate'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    // Logs
    public function emailRegisterLogs($request, $userId, $indicator, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'tbl_id' => $userId,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $logDetails['fields']['password'],
        ]);

        if ($history) {
            $history->update([
                'history_id' => 'history-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for storing password during email registration'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => $indicator == 'freshAccCreate' ? 'REGISTER AN ACCOUNT USING EMAIL' : 'EXISTING ACCOUNT REDIRECTED TO VERIFICATION PAGE',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs during email registration'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for email registration'], Response::HTTP_OK);
    }

    public function verifyEmailLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'SUCCESS VERIFY EMAIL',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for successful email verification'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for successful email verification'], Response::HTTP_OK);
    }

    public function resendVerificationCodeAllLogs($request, $userId, $indicator, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => $indicator ==  env('VERIFY_EMAIL_NUM_CODE') ? 'RESEND NEW VERIFICATION CODE AT VERIFY EMAIL' : ($indicator == env('UPDATE_EMAIL_NUM_CODE') ? 'RESEND NEW VERIFICATION CODE AT USER SETTING UPDATE EMAIL' : 'RESEND NEW VERIFICATION CODE AT USER SETTING UPDATE PASSWORD'),
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for ' . ($indicator == env('VERIFY_EMAIL_NUM_CODE') ? 'resending new verification code at email verification' : ($indicator == env('UPDATE_EMAIL_NUM_CODE') ? 'resending new verification code at user setting email update' : 'resending new verification code at user setting password update'))], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for successful email verification'], Response::HTTP_OK);
    }

    public function forgotPasswordLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'SUCCESSFULLY SENT RESET LINK FOR PASSWORD UPDATE',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for successfully sent reset link for password update'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for successfully sent reset link for password update'], Response::HTTP_OK);
    }

    public function updatePasswordLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        $history = HistoryModel::create([
            'tbl_id' => $userId,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $logDetails['fields']['new_password'],
        ]);

        if ($history) {
            $history->update([
                'history_id' => 'history-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for password storage during password update'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON FORGOT PASSWORD',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for password update'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for password update'], Response::HTTP_OK);
    }

    public function updateEmailOnSettingUserLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'tbl_id' => $userId,
            'tbl_name' => 'users_tbl',
            'column_name' => 'email',
            'value' => $logDetails['fields']['old_email'],
        ]);

        if ($history) {
            $history->update([
                'history_id' => 'history-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE EMAIL ON SETTINGS OF USER',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for update email'], Response::HTTP_OK);
    }

    public function updatePasswordOnSettingUserLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        $history = HistoryModel::create([
            'tbl_id' => $userId,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $logDetails['fields']['new_password'],
        ]);

        if ($history) {
            $history->update([
                'history_id' => 'history-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for update password on user setting'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON USER SETTING',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for update password on user setting'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for update password on user setting'], Response::HTTP_OK);
    }

    public function updateEmailAndPasswordSendVerificationCodeLogs($request, $userId, $indicator, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => $indicator == env('UPDATE_EMAIL_NUM_CODE')
                ? 'RESEND NEW VERIFICATION CODE AT USER SETTING (UPDATE EMAIL)'
                : 'RESEND NEW VERIFICATION CODE AT USER SETTING (UPDATE PASSWORD)',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for ' . ($indicator == env('VERIFY_EMAIL_NUM_CODE') ? 'resending new verification code at email verification' : ($indicator == env('UPDATE_EMAIL_NUM_CODE') ? 'resending new verification code at user setting email update' : 'resending new verification code at user setting password update'))], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history for successful email verification'], Response::HTTP_OK);
    }

    public function loginLogs($request, $userId)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'ip_address' => $request->ip(),
            'user_action' => 'LOGIN',
            'user_device' => $userAgent,
            'details' => json_encode([
                'user_id' => $userId,
                'fields' => [
                    'ip_address' => $request->ip(),
                ]
            ], JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-' . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs login'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history login'], Response::HTTP_OK);
    }

    public function updateEmailAdminLogs($request, $userIdClient, $userConfigIdHash, $data)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'user_id' => $userIdClient,
            'changed_fields' => $data, // Use the provided data array
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'user_id' => $userIdClient,
            'tbl_name' => 'users_tbl',
            'column_name' => 'email',
            'value' => $data['old_email'],
        ]);

        if (!$history) {
            return response()->json(['message' => 'Failed to create history for update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id' => $userConfigIdHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE EMAIL ON ADMIN DASHBOARD',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updatePasswordAdminLogs($request, $userIdClient, $userConfigIdHash, $data)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'user_id' => $userIdClient,
            'changed_fields' => $data, // Use the provided data array
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'user_id' => $userIdClient,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $data['old_password'],
        ]);

        if (!$history) {
            return response()->json(['message' => 'Failed to create history for update password'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id' => $userConfigIdHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON ADMIN DASHBOARD',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update password'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateRoleAndStatusLogs($request, $userId, $userConfigIdHash, $changesForLogs)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'user_id' => $userId,
            'changed_fields' => [],
        ];

        // Loop through changesForLogs and encrypt old and new values before adding to logDetails
        foreach ($changesForLogs as $field => $change) {
            $logDetails['changed_fields'][$field] = [
                'old' => $change['old'],
                'new' => $change['new'],
            ];

            // Create HistoryModel entry
            $history = HistoryModel::create([
                'tbl_id' => $userId,
                'tbl_name' => 'users_tbl',
                'column_name' => $field, // Use the field name as the column name
                'value' => $change['old'],
            ]);

            if ($history) {
                $history->update([
                    'history_id' => 'history-'  . $history->id,
                ]);
            } else {
                return response()->json(['message' => 'Failed to create history for update role and status'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userConfigIdHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE ROLE OR STATUS',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for update role and status'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully update logs for update role and status'], Response::HTTP_OK);
    }
}
