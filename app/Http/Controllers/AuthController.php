<?php

namespace App\Http\Controllers;

use App\Models\AuthModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use App\Mail\VerificationMail;
use Illuminate\Support\Carbon;
use App\Mail\ResetPasswordMail;
use App\Models\OldPasswordModel;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Mail\ResendVerificationMail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;

use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{

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
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Decrypt al email first
        $users = AuthModel::all();
        foreach ($users as $userModel) {
            $decryptedEmail = Crypt::decrypt($userModel->email);

            // Check if Verified Email
            if ($decryptedEmail == $request->input("email") && Hash::check($request->input('password'), $userModel->password) && $userModel->email_verified_at !== NULL) {
                try {
                    // $expirationTime = Carbon::now()->addSeconds(30);
                    // Expiration Time 1month
                    $expirationTime = Carbon::now()->addMinutes(2592000);
                    $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($userModel);
                    if (!$newToken) {
                        return response()->json([
                            'error' => 'Token generation failed',
                            'message' => 'Unable to generate a token from user'
                        ], Response::HTTP_OK);
                    }

                    $userModel->session_token = $newToken;
                    $userModel->session_expire_at = $expirationTime;
                    if (!$userModel->save()) {
                        return response()->json(
                            [
                                'message' => 'Error To update session token and expiration'
                            ],
                            Response::HTTP_INTERNAL_SERVER_ERROR
                        );
                    }

                    // Check If users_info_tbl exist 
                    $userInfo = UserInfoModel::where('user_id_hash', $userModel->id_hash)
                        ->where(function ($query) {
                            $query->whereNull('first_name')->orWhere('first_name', '');
                            $query->orWhereNull('last_name')->orWhere('last_name', '');
                        })
                        ->first();

                    return response()->json([
                        'role' => $userModel->role === 'USER' ? $userRole : ($userModel->role === 'ADMIN' ? $adminRole : ($userModel->role === 'STAFF' ? $staffRole : '')),
                        'user' => $userModel,
                        'user_info' => $userInfo ? 'New User' : 'Existing User',
                        'token_type' => 'Bearer',
                        'access_token' => $newToken,
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                        'message' => 'Login Successfully'
                    ], Response::HTTP_OK);
                } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
                    return response()->json([
                        'status' => 0,
                        'message' => $e->getMessage(),
                    ], Response::HTTP_OK);
                }

                break;
            }
            // Check if Not Verified then redirect to Verify Email
            else if ($decryptedEmail == $request->input("email") && Hash::check($request->input('password'), $userModel->password) && $userModel->email_verified_at === NULL) {
                // Generate a new token for the user
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($userModel);

                if (!$newToken) {
                    return response()->json([
                        'error' => 'Token generation failed',
                        'message' => 'Unable to generate a token from user'
                    ], Response::HTTP_OK);
                }

                // Update verification_number | password | verify email token
                $userModel->verification_number = $verificationNumber;
                $userModel->verify_email_token = $newToken;
                $userModel->verify_email_token_expire_at = $expirationTime;

                // Save
                if (!$userModel->save()) {
                    return response()->json(
                        [
                            'error' => 'Error To update to verification number, token and expiration time'
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
            // Wrong Credentials
            else {
                return response()->json(['error' => 'Invalid credentials'], Response::HTTP_UNAUTHORIZED);
            }
        }
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
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['error' => $validator->errors()],  Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }
        // Check if Email is not empty
        else if ($request->input('email') !== '' || $request->input('email') !== null && ($request->input('phone_number') === '' || $request->input('phone_number') === null)) {
            // Validate Password
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['error' => $validator->errors()], Response::HTTP_NOT_FOUND);
            }

            return $this->emailRegister($idHash, $verificationNumber, $roleUser, $status, $request->input('email'), $request->input('password'));
        } else {
            return response()->json(['error' => 'Please Input on Phone Number or Email', Response::HTTP_UNPROCESSABLE_ENTITY], 0);
        }
    }

    // CHILD REGISTER EMAIL
    public function emailRegister($idHash, $verificationNumber, $roleUser, $status, $email, $password)
    {
        // Get All Users and Decrypt
        $users = AuthModel::all();
        $decryptDatas = [];

        // Decrypt
        foreach ($users as $user) {
            // Start Decrypt
            $decryptData = Crypt::decrypt($user->email);

            // Append the decrypted data to the array along with email_verified_at
            $decryptDatas[] = [
                'email' => $decryptData,
                'email_verified_at' => $user->email_verified_at,
            ];
        }

        // Check if the requested email exists in the decrypted emails and email_verified_at is not null
        foreach ($decryptDatas as $data) {
            if ($data['email'] === $email && $data['email_verified_at'] === null) {
                // Generate a new token for the user
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

                if (!$newToken) {
                    return response()->json([
                        'error' => 'Token generation failed',
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
                            'error' => 'Error To update to verification number, token and expiration time'
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Get the Name of Gmail
                $emailParts = explode('@', $email);
                $name = [$emailParts[0]];

                // Send the new token to the user via email
                Mail::to($email)->send(new VerificationMail($verificationNumber, $name));

                return response()->json(
                    [
                        'message' => 'Successfully create token',
                        'url_token' => '/signup/verify-email?tj=' . $newToken,
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),

                    ],
                    Response::HTTP_OK
                );
            } else if ($data['email'] === $email && $data['email_verified_at'] !== null) {
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
            'verification_number' => rand(100000, 999999),
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
        Mail::to($email)->send(new VerificationMail($verificationNumber, $name));

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
            return response()->json(['error' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Check if the provided verification number matches the stored one
        if ($user->verification_number == $request->verification_number) {
            // Update user status and set email_verified_at to the current timestamp
            $user->update([
                'status' => 'ACTIVE',
                'verify_email_token' => Str::uuid(),
                'email_verified_at' => now(),
                'verification_number' => $verificationNumber,
            ]);

            return response()->json(['message' => 'Email verified successfully'], Response::HTTP_OK);
        }

        return response()->json(['error' => 'Invalid verification number'], Response::HTTP_BAD_REQUEST);
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

            Mail::to(Crypt::decrypt($user->email))->send(new ResendVerificationMail($verificationNumber, $name));

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
        $decryptDatas = [];

        // Decrypt
        foreach ($users as $user) {
            // Start Decrypt
            $decryptData = Crypt::decrypt($user->email);

            // Append the decrypted data to the array along with email_verified_at
            $decryptDatas[] = [
                'email' => $decryptData,
                'email_verified_at' => $user->email_verified_at,
            ];
        }

        // Check if the requested email exists in the decrypted emails and email_verified_at is not null
        foreach ($decryptDatas as $data) {
            if ($data['email'] === $request->email && $data['email_verified_at'] !== null) {
                // 2hrs expiration to verified Email
                $expirationTime = Carbon::now()->addMinutes(120);
                $newToken = JWTAuth::claims(['exp' => $expirationTime->timestamp])->fromUser($user);

                // Update token and expiration
                $user->reset_password_token = $newToken;
                $user->reset_password_token_expire_at = $expirationTime;

                // Save
                if (!$user->save()) {
                    return response()->json(
                        [
                            'error' => 'Error to save token and expiration',
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Send to Email Now
                Mail::to($request->email)->send(new ResetPasswordMail($newToken, $request->email, $expirationTime));

                return response()->json(
                    [
                        'expire_at' => $expirationTime->diffInSeconds(Carbon::now()),
                        'message' => 'Successfully sent the update password link to your ' . $request->email,
                        'token' => $newToken,
                    ],
                    Response::HTTP_OK
                );
            }
        }
        return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
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
                return response()->json(['error' => $validator->errors()], Response::HTTP_BAD_REQUEST);
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
                $userOldPass = OldPasswordModel::create([
                    'user_id_hash' => $user->id_hash,
                    'password' => $existingUser->password,
                ]);

                // Check if storing old password is successful
                if ($userOldPass) {
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

    // GLOBAL FUNCTIONS
    // Code to check if authenticate users
    public function authorizeUserLogin($request)
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
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();

            if (!$bearerToken || $user->reset_password_token !== $bearerToken || $user->reset_password_token_expire_at < Carbon::now()) {
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

    public function authorizeUserResendCode($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();

            if (!$bearerToken || $user->verify_email_token !== $bearerToken || $user->verify_email_token_expire_at < Carbon::now()) {
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
                return response()->json(['error' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Get the bearer token from the headers
            $bearerToken = $request->bearerToken();
            if (!$bearerToken || $user->verify_email_token !== $bearerToken || $user->verify_email_token_expire_at < Carbon::now()) {
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
}
