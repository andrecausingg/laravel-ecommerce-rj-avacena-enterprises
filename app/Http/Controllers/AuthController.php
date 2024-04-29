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
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

    protected $helper, $fillableAttrAuths, $UnsetForRetreives, $ArrHaveAtConvertToReadDateTime, $ArrEnvRoles;

    public function __construct(Helper $helper, AuthModel $fillableAttrAuths)
    {
        $this->UnsetForRetreives = config('system.accounts.UnsetForRetreiveIndex');
        $this->ArrHaveAtConvertToReadDateTime = config('system.accounts.ArrHaveAtConvertToReadDateTime');
        $this->ArrEnvRoles = config('system.accounts.ArrEnvRole');

        $this->helper = $helper;
        $this->fillableAttrAuths = $fillableAttrAuths;
    }

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
                    $resultLogs = $this->loginLogs($request, $user->user_id);

                    return response()->json([
                        'role' => $user->role === $clientRole ? $clientRole : ($user->role === $adminRole ? $adminRole : ($user->role === $delivery ? $delivery : ($user->role === $cashier ? $cashier : ''))),
                        // 'user' => $user,
                        'user_info' => $userInfoExists ? 'Existing User' : 'New User',
                        'token_type' => 'Bearer',
                        'access_token' => $newToken,
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                        'message' => 'Login Successfully',
                        'log_message' => $resultLogs
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

    /**
     * PARENT REGISTER
     * Register a new user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        // Declare Value
        $verification_number = mt_rand(100000, 999999);
        $account_role = env('ROLE_CLIENT');
        $status = 'PENDING';
        $arr_data = [];

        do {
            $user_id = Str::uuid()->toString();
        } while (AuthModel::where('user_id', $user_id)->exists());

        $arr_data = [
            'user_id' => $user_id,
            'verification_number' => $verification_number,
            'account_role' => $account_role,
            'status' => $status,
        ];

        // Check if phone number is not empty
        if (($request->input('phone_number') !== '' || $request->input('phone_number') !== null) && ($request->input('email') === '' || $request->input('email') === null)) {
            $validator = Validator::make($request->all(), [
                'phone_number' => 'required|numeric',
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            $arr_data['phone_number'] = $request->phone_number;
            $arr_data['password'] = $request->password;

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

            $arr_data['email'] = $request->email;
            $arr_data['password'] = $request->password;

            return $this->emailRegister($request, $arr_data);
        }

        return response()->json(['message' => 'Please Input on Phone Number or Email', Response::HTTP_UNPROCESSABLE_ENTITY], 0);
    }

    /**
     * CHILD REGISTER EMAIL
     * Register a new user for email.
     *
     * @param array $arr_data
     * @return \Illuminate\Http\JsonResponse
     */
    public function emailRegister($request, $arr_data)
    {
        // Generate a new token for the user
        $expiration_time = Carbon::now()->addMinutes(120);
        // Get All Users and Decrypt
        $users = AuthModel::all();

        // Decrypt
        foreach ($users as $user) {
            // Start Decrypt
            $decrypted_email = Crypt::decrypt($user->email);

            // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
            if ($decrypted_email === $arr_data['email'] && $user->email_verified_at === null) {
                $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);
                if (!$new_token) {
                    return response()->json([
                        'message' => 'Unable to generate a token from user'
                    ], Response::HTTP_OK);
                }

                // Update verification_number | password | verify email token
                $user->verification_number = $arr_data['verification_number'];
                $user->password = Hash::make($arr_data['password']);
                $user->verify_email_token = $new_token;
                $user->verify_email_token_expire_at = $expiration_time;

                // Save
                if (!$user->save()) {
                    return response()->json(
                        [
                            'message' => 'Error updating password, verification number, new token, and expiration time',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Arr Logs details
                $arr_log_details = [
                    'fields' => [
                        'user_id' => $user->user_id,
                        'email' => Crypt::encrypt($arr_data['email']),
                        'password' => Crypt::encrypt($arr_data['password']),
                    ]
                ];

                // Arr Data Logs
                $arr_data_logs = [
                    'user_id' => $user->user_id,
                    'is_sensitive' => 1,
                    'is_history' => 1,
                    'log_details' => $arr_log_details,
                    'user_action' => 'EXISTING ACCOUNT REDIRECTED TO VERIFICATION PAGE',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);

                // Get the Name of Gmail
                $email_parts = explode('@', $arr_data['email']);
                $name = [$email_parts[0]];

                // Send the new token to the user via email
                $email = Mail::to($arr_data['email'])->send(new VerificationMail($arr_data['verification_number'], $name));
                if (!$email) {
                    return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
                return response()->json([
                    'message' => 'Successfully create token',
                    // 'data' => $user,
                    'url_token' => '/signup/verify-email?tj=' . $new_token,
                    'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
                    'log_message' => $log_result
                ], Response::HTTP_OK);
            }

            // If same email exist and email_verified_at not null send error message
            else if ($decrypted_email === $arr_data['email'] && $user->email_verified_at !== null) {

                return response()->json(
                    [
                        'message' => 'Email already exist'
                    ],
                    Response::HTTP_UNPROCESSABLE_ENTITY
                );
            }
        }

        // User with the given email does not exist, create a new user
        $user_create = AuthModel::create([
            'user_id' => $arr_data['user_id'],
            'email' => Crypt::encrypt($arr_data['email']),
            'password' => Hash::make($arr_data['password']),
            'role' => $arr_data['account_role'],
            'status' => $arr_data['status'],
            'verification_number' => $arr_data['verification_number'],
        ]);

        if (!$user_create) {
            // Error creating user
            return response()->json(['message' => 'Failed to create user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user_create);

        if (!$new_token) {
            return response()->json(['message' => 'Failed to generate token'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Update user with the new token for email verification
        $user_create->verify_email_token = $new_token;
        $user_create->verify_email_token_expire_at = $expiration_time;

        if (!$user_create->save()) {
            return response()->json(['message' => 'Failed to update token and expire at'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Arr Logs details
        $arr_log_details = [
            'fields' => [
                'user_id' => $arr_data['user_id'],
                'email' => Crypt::encrypt($arr_data['email']),
                'password' => Crypt::encrypt($arr_data['password']),
            ]
        ];

        // Arr Data Logs
        $arr_data_logs = [
            'user_id' => $arr_data['user_id'],
            'is_sensitive' => 1,
            'is_history' => 1,
            'log_details' => $arr_log_details,
            'user_action' => 'REGISTER AN ACCOUNT USING EMAIL',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        // Get the Name of Gmail
        $emailParts = explode('@', $arr_data['email']);
        $name = $emailParts[0];

        // Send an email to the user with the new token
        $email = Mail::to($arr_data['email'])->send(new VerificationMail($arr_data['verification_number'], $name));
        if (!$email) {
            return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json([
            'message' => 'Successfully create token',
            'url_token' => '/signup/verify-email?tj=' . $new_token,
            'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }

    /**
     * CHILD EMAIL REGISTER
     * Verify email
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyEmail(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);

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
        $expiration_time = Carbon::now()->addSecond();
        $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);

        // Update user status and set email_verified_at to the current timestamp
        $user->status = 'ACTIVE';
        $user->verify_email_token = $new_token;
        $user->email_verified_at = now();
        $user->verification_number = $verification_number;

        if (!$user->save()) {
            return response()->json(
                [
                    'message' => 'Failed to verify email',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Log Details
        $log_details = [
            'fields' => [
                'user_id' => $user->user_id,
                'email_verified_at' => $user->email_verified_at,
                'verification_number' => $request->verification_number,
            ]
        ];

        // Arr Data Logs
        $arr_data_logs = [
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $log_details,
            'user_action' => 'SUCCESS VERIFY EMAIL',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json(
            [
                'message' => 'Email verified successfully',
                'log_message' => $log_result
            ],
            Response::HTTP_OK
        );
    }

    // SIGN UP | VERIFY EMAIL RESEND CODE
    public function resendVerificationAuth(Request $request)
    {
        $logDetails = [];
        $verification_number = mt_rand(100000, 999999);

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

        if ($user->update([
            'verification_number' => $verification_number,
        ])) {
            $emailParts = explode('@', Crypt::decrypt($user->email));
            $name = [$emailParts[0]];

            if ($request->indicator == env('VERIFY_EMAIL_NUM_CODE')) {
                $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verification_number, $name));
                if (!$email) {
                    return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            $logDetails = [
                'fields' => [
                    'user_id' => $user->user_id,
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
                $expiration_time = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);

                // Update token and expiration
                $user->reset_password_token = $newToken;
                $user->reset_password_token_expire_at = $expiration_time;

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
                    'fields' => [
                        'user_id' => $user->user_id,
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
            'fields' => [
                'user_id' => $user->user_id,
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
        $user = $this->helper->authorizeUser($request);
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
                'fields' => [
                    'user_id' => $user->user_id,
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
                $logResult = $this->updatePasswordOnSettingUserLogs($request, $user->user_id, $logDetails);
                return response()->json([
                    'message' => 'Password updated successfully',
                    'log_message' => $logResult
                ], Response::HTTP_OK);
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
        $user = $this->helper->authorizeUser($request);
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
                'fields' => [
                    'user_id' => $user->user_id,
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
        $user = $this->helper->authorizeUser($request);
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
                'fields' => [
                    'user_id' => $user->user_id,
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
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Decrypt all emails and other attributes
        $decryptedAuthUser = [];
        $columnName = [];

        // Unset Column not needed
        $unsetResults = $this->helper->unsetColumn($this->UnsetForRetreives, $this->fillableAttrAuths->getFillableAttributes());

        // Retrieve all AuthModel records
        $authUsers = AuthModel::all();

        foreach ($authUsers as $authUser) {
            foreach ($unsetResults as $column) {
                if ($column == 'user_id') {
                    $userInfo = UserInfoModel::where('user_id', $authUser->user_id)->first();
                    $decryptedAuthUser['data']['userInfo'] = [
                        'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                    ];
                    $decryptedAuthUser['data']['id'] = Crypt::encrypt($authUser->{$column});
                    $columnName[] = $this->helper->transformColumnName('Id');
                } else if ($column == 'email') {
                    $decryptedAuthUser['data'][$column] = $authUser->{$column} ? Crypt::decrypt($authUser->{$column}) : null;
                    $history = HistoryModel::where('tbl_id', $authUser->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
                    $decryptedAuthUser['data']['password'] = $history ? Crypt::decrypt($history->value) : null;
                    $columnName[] = $this->helper->transformColumnName($column);
                    $columnName[] = 'password';
                } else if ($column == 'role') {
                    $columnName[] = $this->helper->transformColumnName($column);
                    foreach ($this->ArrEnvRoles as $roleEnv => $roleLabel) {
                        if ($authUser->{$column} == env($roleEnv)) {
                            $decryptedAuthUser['data'][$column] = $roleLabel;
                            break;
                        }
                    }
                } else {
                    // Keep other columns as they are
                    $columnName[] = $this->helper->transformColumnName($column);
                    $value = $authUser->{$column};

                    // Check if the column needs formatting and value is not null
                    if (in_array($column, $this->ArrHaveAtConvertToReadDateTime) && $value !== null) {
                        // Format the value using Carbon
                        $carbonDate = Carbon::parse($value);
                        $value = $carbonDate->format('F j, Y g:i a');
                    }

                    // Assign the value to the decryptedAuthUser array
                    $decryptedAuthUser['data'][$column] = $value;
                }
            }
        }

        // Add new columns
        $newColumns = [
            "User Info",
            "Action"
        ];
        $transformedColumns = array_map(function ($columnName) {
            return $this->helper->transformColumnName($columnName);
        }, $columnName);
        array_unshift($transformedColumns, $this->helper->transformColumnName($newColumns[0]));
        array_push($transformedColumns, $this->helper->transformColumnName($newColumns[1]));

        $decryptedAuthUser['column'] = $transformedColumns;

        $crudSettings = $this->getApiAccountCrudSettings();
        $decryptedAuthUser['data']['action'] = $this->helper->functionsApiAccountsCrud(
            $crudSettings['prefix'],
            $crudSettings['apiWithPayloads'],
            $crudSettings['methods'],
            $crudSettings['buttonNames'],
            $crudSettings['icons'],
            $crudSettings['actions']
        );

        $relativeSettings = $this->getApiAccountRelativeSettings();
        $decryptedAuthUser['relative'] = $this->helper->functionRelative(
            $relativeSettings['prefix'],
            $relativeSettings['apiWithPayloads'],
            $relativeSettings['methods'],
            $relativeSettings['buttonNames'],
            $relativeSettings['icons'],
            $relativeSettings['actions']
        );

        // Display or use the decrypted attributes as needed
        return response()->json(['messages' => [$decryptedAuthUser]], Response::HTTP_OK);
    }

    private function getApiAccountCrudSettings()
    {
        $prefix = 'accounts/';
        $apiWithPayloads = [
            'update-email' => ['id', 'new_email'],
            'update-password' => ['id', 'password', 'password_confirmation'],
            'update-role-status' => ['id', 'role', 'status'],
        ];
        $methods = [
            'update-email' => 'POST',
            'update-password' => 'POST',
            'update-role-status' => 'POST',
        ];
        $buttonNames = [
            'update-email' => 'update-email',
            'update-password' => 'update-password',
            'update-role-status' => 'update-role-status',
        ];
        $icons = [
            'update-email' => null,
            'update-password' => null,
            'update-role-status' => null,
        ];
        $actions = [
            'update-email' => 'modal',
            'update-password' => 'modal',
            'update-role-status' => 'modal',
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }

    private function getApiAccountRelativeSettings()
    {
        $prefix = 'accounts/';
        $apiWithPayloads = [
            'store' => [
                'email',
                'password',
                'password_confirmation',
                'role',
                'status'
            ],
            'show/' => [
                'id',
            ]
        ];

        $methods = [
            'store' => 'POST',
            'show/' => 'GET',
        ];

        $buttonNames = [
            'store' => 'create',
            'show/' => null,
        ];

        $icons = [
            'store' => null,
            'show/' => null,
        ];

        $actions = [
            'store' => 'modal',
            'show/' => null,
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }

    // GET SPECIFIC USER ACCOUNT | ADMIN SIDE
    public function show(Request $request, string $id)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        if (empty($id) || $id == null || $id == '') {
            return response()->json(['message' => 'Invalid I.D'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Decrypt all emails and other attributes
        $decryptedAuthUser = [];
        $columnName = [];

        // Unset Column not needed
        $unsetResults = $this->helper->unsetColumn($this->UnsetForRetreives, $this->fillableAttrAuths->getFillableAttributes());

        // Retrieve AuthModel record
        $authUser = AuthModel::where('user_id', Crypt::decrypt($id))->first();

        if (!$authUser) {
            return response()->json(['message' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        foreach ($unsetResults as $column) {
            if ($column == 'user_id') {
                $userInfo = UserInfoModel::where('user_id', $authUser->user_id)->first();
                $decryptedAuthUser['data']['userInfo'] = [
                    'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                ];
                $decryptedAuthUser['data']['id'] = Crypt::encrypt($authUser->{$column});
                $columnName[] = $this->helper->transformColumnName('Id');
            } else if ($column == 'email') {
                $decryptedAuthUser['data'][$column] = $authUser->{$column} ? Crypt::decrypt($authUser->{$column}) : null;
                $history = HistoryModel::where('tbl_id', $authUser->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
                $decryptedAuthUser['data']['password'] = $history ? Crypt::decrypt($history->value) : null;
                $columnName[] = $this->helper->transformColumnName($column);
                $columnName[] = 'password';
            } else if ($column == 'role') {
                $columnName[] = $this->helper->transformColumnName($column);
                foreach ($this->ArrEnvRoles as $roleEnv => $roleLabel) {
                    if ($authUser->{$column} == env($roleEnv)) {
                        $decryptedAuthUser['data'][$column] = $roleLabel;
                        break;
                    }
                }
            } else {
                // Keep other columns as they are
                $columnName[] = $this->helper->transformColumnName($column);
                $value = $authUser->{$column};

                // Check if the column needs formatting and value is not null
                if (in_array($column, $this->ArrHaveAtConvertToReadDateTime) && $value !== null) {
                    // Format the value using Carbon
                    $carbonDate = Carbon::parse($value);
                    $value = $carbonDate->format('F j, Y g:i a');
                }

                // Assign the value to the decryptedAuthUser array
                $decryptedAuthUser['data'][$column] = $value;
            }
        }

        // Add new columns
        $newColumns = [
            "User Info",
            "Action"
        ];
        $transformedColumns = array_map(function ($columnName) {
            return $this->helper->transformColumnName($columnName);
        }, $columnName);
        array_unshift($transformedColumns, $this->helper->transformColumnName($newColumns[0]));
        array_push($transformedColumns, $this->helper->transformColumnName($newColumns[1]));

        // Display or use the decrypted attributes as needed
        return response()->json(['messages' => [$decryptedAuthUser]], Response::HTTP_OK);
    }

    // UPDATE EMAIL | ADMIN SIDE
    public function updateEmailAdmin(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules
        $validator = Validator::make($request->all(), [
            'id' => 'required|string',
            'new_email' => 'required|email',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', Crypt::decrypt($request->user_id))->first();
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
                $logResult = $this->updateEmailAdminLogs($request,  $user->user_id, $logsData);

                return response()->json([
                    'message' => 'Email updated successfully',
                    'log_message' => $logResult
                ], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // UPDATE PASSWORD | ADMIN SIDE
    public function updatePasswordAdmin(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }


        // Validation rules
        $validator = Validator::make($request->all(), [
            'id' => 'required|string',
            'password' => 'required|string|min:6|confirmed:password_confirmation',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', Crypt::decrypt($request->user_id))->first();
        if (!$userAuth) {
            return response()->json(['message' => 'Data Not Found'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        if (Hash::check($request->new_password, $userAuth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            $history = HistoryModel::where('column_name', 'password')
                ->where('tbl_name', 'users_tbl')
                ->where('tbl_id', Crypt::decrypt($request->user_id))
                ->latest() // Order by created_at column in descending order (latest first)
                ->first(); // Retrieve the first result

            // Store old and new passwords
            $logsData = [
                'old_password' => $history->value,
                'new_password' => Crypt::encrypt($request->input('password')),
            ];

            // Update the user password
            $userAuth->password = Hash::make($request->input('password'));

            // Saving
            if ($userAuth->save()) {
                // Logs
                $logResult = $this->updatePasswordAdminLogs($request,  $user->user_id, $logsData);
                return response()->json([
                    'message' => 'Password updated successfully',
                    'log_message' => $logResult
                ], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // UPDATE ROLE AND STATUS | ADMIN SIDE
    public function updateRoleAndStatus(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }


        // Validation rules
        $validator = Validator::make($request->all(), [
            'id' => 'required|string',
            'role' => 'required|string|max:255',
            'status' => 'required|string|max:255',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('user_id', Crypt::decrypt($request->user_id))->first();
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
                $logResult = $this->updateRoleAndStatusLogs($request,  $user->user_id, $changesForLogs);
                return response()->json([
                    'message' => 'Role and Status updated successfully',
                    'log_message' => $logResult
                ], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update Role and Status'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        } else {
            return response()->json(['message' => 'No changes to update'], Response::HTTP_OK);
        }
    }

    // Authenticate Token
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
                'history_id' => 'history_id-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for storing password during email registration'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => $indicator == 'freshAccCreate' ? 'REGISTER AN ACCOUNT USING EMAIL' : 'EXISTING ACCOUNT REDIRECTED TO VERIFICATION PAGE',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
            'is_sensitive' => 0,
            'ip_address' => $request->ip(),
            'user_action' => 'SUCCESS VERIFY EMAIL',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs for successful email verification'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs for successful email verification'], Response::HTTP_OK);
    }

    public function resendVerificationCodeAllLogs($request, $userId, $indicator, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 0,
            'ip_address' => $request->ip(),
            'user_action' => $indicator ==  env('VERIFY_EMAIL_NUM_CODE') ? 'RESEND NEW VERIFICATION CODE AT VERIFY EMAIL' : ($indicator == env('UPDATE_EMAIL_NUM_CODE') ? 'RESEND NEW VERIFICATION CODE AT USER SETTING UPDATE EMAIL' : 'RESEND NEW VERIFICATION CODE AT USER SETTING UPDATE PASSWORD'),
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'SUCCESSFULLY SENT RESET LINK FOR PASSWORD UPDATE',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
                'history_id' => 'history_id-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history id for password during password update'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON FORGOT PASSWORD',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE EMAIL ON SETTINGS OF USER',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
                'history_id' => 'history_id-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for update password on user setting'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON USER SETTING',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
            'is_sensitive' => 0,
            'ip_address' => $request->ip(),
            'user_action' => $indicator == env('UPDATE_EMAIL_NUM_CODE')
                ? 'RESEND NEW VERIFICATION CODE AT USER SETTING (UPDATE EMAIL)'
                : 'RESEND NEW VERIFICATION CODE AT USER SETTING (UPDATE PASSWORD)',
            'user_device' => $userAgent,
            'details' => json_encode($logDetails, JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
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
            'is_sensitive' => 0,
            'ip_address' => $request->ip(),
            'user_action' => 'LOGIN',
            'user_device' => $userAgent,
            'details' => json_encode([
                'fields' => [
                    'user_id' => $userId,
                    'ip_address' => $request->ip(),
                ]
            ], JSON_PRETTY_PRINT),
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-' . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to store logs login'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs login'], Response::HTTP_OK);
    }

    public function updateEmailAdminLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');
        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = $logDetails;

        $details = json_encode($arr, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE EMAIL ON ADMIN DASHBOARD',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs update email'], Response::HTTP_OK);
    }

    public function updatePasswordAdminLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');
        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = $logDetails;

        $history = HistoryModel::create([
            'tbl_id' => $userId,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $arr['fields']['old_password'],
        ]);

        if ($history) {
            $history->update([
                'history_id' => 'history_id-'  . $history->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to create history for password storage during password update'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $details = json_encode($arr, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE PASSWORD ON ADMIN DASHBOARD',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs update password'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully stored logs and history update password'], Response::HTTP_OK);
    }

    public function updateRoleAndStatusLogs($request, $userId, $logDetails)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');
        $arr = [];
        $arr['user_id'] = $userId;
        $arr['fields'] = $logDetails;

        $details = json_encode($arr, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $log = LogsModel::create([
            'user_id' => $userId,
            'is_sensitive' => 1,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE ROLE OR STATUS',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if ($log) {
            $log->update([
                'log_id' => 'log_id-'  . $log->id,
            ]);
        } else {
            return response()->json(['message' => 'Failed to update logs for update role and status'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Successfully update logs for update role and status'], Response::HTTP_OK);
    }
}
