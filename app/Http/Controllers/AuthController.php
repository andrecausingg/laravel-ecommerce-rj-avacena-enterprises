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
use App\Mail\ResendVerificationMail;
use Illuminate\Support\Facades\Hash;

use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

    // return response()->json([
    //     'id' => $user->id,
    //     'email_db' => $decryptedEmail,
    //     'email_input' => $request->input('email'),
    //     'user' => $user,
    // ], Response::HTTP_OK);
    public function login(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);
        $userRole = '1a409bb7-c650-4829-9162-a73555880c43';
        $adminRole = 'c2dbf655-7fa5-49e0-ba1f-5e35440444d4';
        $staffRole = '01887426-98ed-4bc5-bbd5-5e7a8462ff83';

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
                    $userInfoExists = UserInfoModel::where('user_id_hash', $user->id_hash)
                        ->where(function ($query) {
                            $query->whereNull('first_name')->orWhere('first_name', '');
                            $query->orWhereNull('last_name')->orWhere('last_name', '');
                        })
                        ->exists();

                    // Logs
                    $this->loginLogs($request, $user->id_hash);

                    return response()->json([
                        'role' => $user->role === 'USER' ? $userRole : ($user->role === 'ADMIN' ? $adminRole : ($user->role === 'STAFF' ? $staffRole : '')),
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
        $roleUser = 'USER';
        $status = 'PENDING';
        do {
            $idHash = Str::uuid()->toString();
        } while (AuthModel::where('id_hash', $idHash)->exists());

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

            return $this->emailRegister($idHash, $verificationNumber, $roleUser, $status, $request->input('email'), $request->input('password'));
        } else {
            return response()->json(['message' => 'Please Input on Phone Number or Email', Response::HTTP_UNPROCESSABLE_ENTITY], 0);
        }
    }

    // CHILD REGISTER EMAIL
    public function emailRegister($idHash, $verificationNumber, $roleUser, $status, $email, $password)
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
                if (!$user->save()) {
                    return response()->json(
                        [
                            'message' => 'Error To update to verification number, token and expiration time'
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Get the Name of Gmail
                $emailParts = explode('@', $email);
                $name = [$emailParts[0]];

                // Send the new token to the user via email
                $email = Mail::to($email)->send(new VerificationMail($verificationNumber, $name));
                if (!$email) {
                    return response()->json(['message' => 'Failed to send verification number on your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
                return response()->json(
                    [
                        'message' => 'Successfully create token',
                        // 'data' => $user,
                        'url_token' => '/signup/verify-email?tj=' . $newToken,
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),

                    ],
                    Response::HTTP_OK
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
            'id_hash' => $idHash,
            'email' => Crypt::encrypt($email),
            'password' => Hash::make($password),
            'role' => $roleUser,
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

        // Get the Name of Gmail
        $emailParts = explode('@', $email);
        $name = $emailParts[0];

        // Send an email to the user with the new token
        $email = Mail::to($email)->send(new VerificationMail($verificationNumber, $name));
        if (!$email) {
            return response()->json(['message' => 'Failed to send verification number on your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json([
            'message' => 'Successfully create token',
            'url_token' => '/signup/verify-email?tj=' . $newToken,
            'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
        ], Response::HTTP_OK);
    }

    public function verifyEmail(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Token Validation
        $user = $this->authorizeUserVerifyEmail($request);

        // Validate
        $validator = Validator::make($request->all(), [
            'verification_number' => 'required|numeric|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Check if the provided verification number matches the stored one
        if ($user->verification_number = !$request->verification_number) {
            return response()->json(['message' => 'Invalid verification number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Update user status and set email_verified_at to the current timestamp
        $user->update([
            'status' => 'ACTIVE',
            'verify_email_token' => Str::uuid(),
            'email_verified_at' => now(),
            'verification_number' => $verificationNumber,
        ]);

        return response()->json(['message' => 'Email verified successfully'], Response::HTTP_OK);
    }
    public function resendVerificationCode(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Token Validation
        $user = $this->authorizeUserResendCode($request);

        if ($user->update([
            'verification_number' => $verificationNumber,
        ])) {
            $emailParts = explode('@', Crypt::decrypt($user->email));
            $name = [$emailParts[0]];

            $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verificationNumber, $name));
            if (!$email) {
                return response()->json(['message' => 'Failed to send verification number on your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
            return response()->json([
                'message' => 'New verification code sent to your email'
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
                return response()->json(['message' => 'Successfully sent reset password link on your email' . $decryptedEmail], Response::HTTP_OK);
            }
            // If same email exist and email_verified_at equal null send error message
            else if ($decryptedEmail === $request->email && $user->email_verified_at === null) {
                return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
            }
        }
    }

    public function updatePassword(Request $request)
    {
        try {
            // Token Validation
            $user = $this->authorizeUserUpdatePassword($request);

            // Validate Password
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:6|confirmed',
            ]);

            // Check if validation fails
            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
            }

            // Find user by id_hash
            $existingUser = AuthModel::where('id_hash', $user->id_hash)->first();

            // Check if user exists
            if (!$existingUser) {
                return response()->json(['message' => "User doesn't exist"], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Update the user's password
            $existingUser->password = Hash::make($request->password);

            // Check if the password update is successful
            if ($existingUser->save()) {
                // Store old password
                $history = HistoryModel::create([
                    'user_id_hash' => $user->id_hash,
                    'tbl_name' => $user->id_hash,
                    'column_name' => $existingUser->password,
                    'value' => $existingUser->password,
                ]);

                // Check if storing old password is successful
                if ($history) {
                    return response()->json(['message' => 'Successfully to store the old password'], Response::HTTP_INTERNAL_SERVER_ERROR);
                } else {
                    return response()->json(['message' => 'Failed to store old password'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
            } else {
                return response()->json(['message' => 'Failed updated the password'], Response::HTTP_OK);
            }
        } catch (\Exception $e) {
            // Handle exceptions and return an error response with CORS headers
            $errorMessage = $e->getMessage();
            $errorCode = $e->getCode();

            // Create a JSON error response
            $response = [
                'success' => false,
                'error' => [
                    'code' => $errorCode,
                    'message' => $errorMessage,
                ],
            ];

            // Add additional error details if available
            if ($e instanceof \Illuminate\Validation\ValidationException) {
                $response['error']['details'] = $e->errors();
            }

            // Return the JSON error response with CORS headers and an appropriate HTTP status code
            return response()->json($response, Response::HTTP_INTERNAL_SERVER_ERROR)->header('Content-Type', 'application/json');
        }
    }

    // USER SETTING UPDATE PASSWORD AND EMAIL
    public function updatePasswordOnSettingUser(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Validation rules
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'new_password' => 'required|string|confirmed:new_password_confirmation',
            'verification_number' => 'required|numeric|min:6',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('id_hash', $user->id_hash)->first();

        // Check if user exists
        if (!$userAuth) {
            return response()->json(['message' => 'Intruder'], Response::HTTP_NOT_FOUND);
        }

        if (Hash::check($request->input('new_password'), $userAuth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (!Hash::check($request->input('current_password'), $userAuth->password)) {
            return response()->json(['message' => 'Incorrect current password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if ($userAuth->verification_number != $request->input('verification_number')) {
            return response()->json(['message' => 'Incorrect Verification Number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new passwords
            $logsData = [
                'old_password' => $userAuth->password,
                'new_password' => Hash::make($request->input('new_password')),
            ];

            // Update the user's password
            $userAuth->password = $logsData['new_password'];
            $userAuth->verification_number = $verificationNumber;

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updatePasswordOnSettingUserLogs($request, $user->id_hash, $logsData);

                return response()->json(['message' => 'Password updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update new password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    public function updateEmailOnSettingUser(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->authorizeUser($request);

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
        $userAuth = AuthModel::where('id_hash', $user->id_hash)->first();
        // return response()->json(['message' => $userAuth], Response::HTTP_UNPROCESSABLE_ENTITY);

        if (Crypt::decrypt($userAuth->email) == $request->new_email) {
            return response()->json(['message' => 'The new email cannot be the same as the old email. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($userAuth->email) != $request->new_email && !Hash::check($request->input('current_password'), $userAuth->password)) {
            return response()->json(['message' => 'Incorrect password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($userAuth->email) != $request->new_email && Hash::check($request->input('current_password'), $userAuth->password) && $userAuth->verification_number != $request->verification_number) {
            return response()->json(['message' => 'Incorrect verification number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new emails
            $logsData = [
                'old_email' => Crypt::encrypt($userAuth->email),
                'new_email' => Crypt::encrypt($request->new_email),
            ];

            // Update the user's email
            $userAuth->email = $logsData['new_email'];
            $userAuth->verification_number = $verificationNumber;

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updateEmailOnSettingUserLogs($request, $user->id_hash, $logsData);

                return response()->json(['message' => 'Email updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    public function updateEmailAndPasswordSendVerificationCode(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        // Token Validation
        $user = $this->authorizeUserResendCode($request);

        if ($user->update([
            'verification_number' => $verificationNumber,
        ])) {
            $emailParts = explode('@', Crypt::decrypt($user->email));
            $name = [$emailParts[0]];

            $email = Mail::to(Crypt::decrypt($user->email))->send(new ResendVerificationMail($verificationNumber, $name));
            if (!$email) {
                return response()->json(['message' => 'Failed to send verification number on your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
            return response()->json([
                'message' => 'New verification code sent to your email'
            ], Response::HTTP_OK);
        }
    }

    // UPDATE USER SPECIFIC USER EMAIL PASSWORD ROLE AND STATUS
    public function index(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Decrypt all emails and other attributes
        $decryptedAuthUser = [];

        $authUsers = AuthModel::all();

        foreach ($authUsers as $authUser) {
            $decryptedEmail = $authUser->email ? Crypt::decrypt($authUser->email) : null;
            $userInfo = UserInfoModel::where('user_id_hash', $authUser->id_hash)->first(); // Assuming it returns one record

            $decryptedAuthUser[] = [
                'id' => $authUser->id ?? null,
                'id_hash' => $authUser->id_hash ?? null,
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

    public function updateEmail(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        // Validation rules
        $validator = Validator::make($request->all(), [
            'id_hash' => 'required|string',
            'new_email' => 'required|email',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $userAuth = AuthModel::where('id_hash', $request->id_hash)->first();

        $isEmailsExist = AuthModel::get();
        $exist = 0;
        $oldEmail = '';
        foreach ($isEmailsExist as $isEmailExist) {
            $decryptedEmail = strtolower(Crypt::decrypt($isEmailExist->email)) ?? null;
            $newEmail = strtolower($request->new_email);
            if ($decryptedEmail == $newEmail) {
                $exist = 1;
                $oldEmail = $decryptedEmail;
                break;
            }
        }

        if (strtolower(Crypt::decrypt($userAuth->email)) == $newEmail) {
            return response()->json(['message' => 'The new email cannot be the same as the old email. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if ($exist == 1) {
            return response()->json(['message' => 'Email is taken'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Store old and new emails
            $logsData = [
                'old_email' => Crypt::encrypt($oldEmail),
                'new_email' => Crypt::encrypt($newEmail),
            ];

            // Update the user's email
            $userAuth->email = $logsData['new_email'];

            // Saving
            if ($userAuth->save()) {
                // Logs
                $this->updateEmailOnSettingUserLogs($request, $request->id_hash, $logsData);

                return response()->json(['message' => 'Email updated successfully'], Response::HTTP_OK);
            } else {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }

    // GLOBAL FUNCTIONS
    // Code to check if authenticate users
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

    // Logs
    public function updatePasswordOnSettingUserLogs($request, $idHash, $data)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'message' => 'Update password with the following changes:',
            'user_id_hash' => $idHash,
            'changed_fields' => $data, // Use the provided data array
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'user_id_hash' => $idHash,
            'tbl_name' => 'users_tbl',
            'column_name' => 'password',
            'value' => $data['old_password'],
        ]);

        if (!$history) {
            return response()->json(['message' => 'Failed to create history for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE USER PASSWORD IN SETTINGS',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateEmailOnSettingUserLogs($request, $idHash, $data)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'message' => 'Update email with the following changes:',
            'user_id_hash' => $idHash,
            'changed_fields' => $data, // Use the provided data array
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'user_id_hash' => $idHash,
            'tbl_name' => 'users_tbl',
            'column_name' => 'email',
            'value' => $data['old_email'],
        ]);

        if (!$history) {
            return response()->json(['message' => 'Failed to create history for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE USER EMAIL IN SETTINGS',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function loginLogs($request, $idHash)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'message' => 'User Login',
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'LOGIN',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function updateEmailLogs($request, $idHash, $data)
    {
        // Get Device Information
        $userAgent = $request->header('User-Agent');

        // Create a log entry for changed fields
        $logDetails = [
            'message' => 'Update email with the following changes:',
            'user_id_hash' => $idHash,
            'changed_fields' => $data, // Use the provided data array
        ];

        $details = json_encode($logDetails, JSON_PRETTY_PRINT);

        // Create HistoryModel entry for old password
        $history = HistoryModel::create([
            'user_id_hash' => $idHash,
            'tbl_name' => 'users_tbl',
            'column_name' => 'email',
            'value' => $data['old_email'],
        ]);

        if (!$history) {
            return response()->json(['message' => 'Failed to create history for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Create LogsModel entry
        $logEntry = LogsModel::create([
            'user_id_hash' => $idHash,
            'ip_address' => $request->ip(),
            'user_action' => 'UPDATE EMAIL ON ADMIN DASHBOARD',
            'user_device' => $userAgent,
            'details' => $details,
        ]);

        if (!$logEntry) {
            return response()->json(['message' => 'Failed to update logs for update user info'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
