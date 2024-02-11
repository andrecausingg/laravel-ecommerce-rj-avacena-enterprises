<?php

namespace App\Http\Controllers;

use App\Models\AuthModel;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Mail\VerificationMail;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{


    public function register(Request $request)
    {
        // Declare Value
        $verificationNumber = mt_rand(100000, 999999);
        $roleUser = 'USER';
        $status = 'PENDING';
        do {
            $idHash = Str::uuid()->toString();
        } while (AuthModel::where('id_hash', $idHash)->exists());

        if (($request->input('phone_number') !== '' || $request->input('phone_number') !== null) && ($request->input('email') === '' || $request->input('email') === null)) {
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['error' => $validator->errors()], 400);
            }
        } else if ($request->input('email') !== '' || $request->input('email') !== null && ($request->input('phone_number') === '' || $request->input('phone_number') === null)) {
            // Validate Password
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:6|confirmed:password_confirmation',
            ]);

            if ($validator->fails()) {
                return response()->json(['error' => $validator->errors()], Response::HTTP_NOT_FOUND);
            }

            return $this->emailRegister($idHash, $verificationNumber, $roleUser, $status, $request->input('email'), $request->input('password'), $request->input('password_confirmation'));
        } else {
            return response()->json(['error' => 'Please Input on Phone Number or Email', Response::HTTP_UNPROCESSABLE_ENTITY], 0);
        }
    }

    public function emailRegister($idHash, $verificationNumber, $roleUser, $status, $email, $password, $password_confirmation)
    {
        try {
            $notExist = 0;
            // Get All Users and Decrypt Email
            $users = AuthModel::all();
            foreach ($users as $user) {
                try {
                    // Start Decrypt
                    $decryptedEmail = Crypt::decrypt($user->email);
                    // If Exist the email
                    if ($decryptedEmail == $email) {
                        // Not verified yet then send code
                        if ($user->email_verified_at == NULL) {

                            // Update Verification Number | Password
                            $user->verification_number = $verificationNumber;
                            $user->password = Hash::make($password);

                            // Save
                            if ($user->save()) {
                                // Get the Name of Gmail
                                $emailParts = explode('@', $email);
                                $name = [$emailParts[0]];

                                // Set expiration time to 2 hours (120 minutes)
                                $expiration = Carbon::now()->addMinutes(120);
                                // Generate JWT token with a custom expiration time
                                $token = JWTAuth::fromUser($user, ['exp' => $expiration->timestamp]);

                                // Send to Email Now
                                Mail::to($email)->send(new VerificationMail($verificationNumber, $name));

                                return response()->json(
                                    [
                                        'token' => $token,
                                        'message' => 'Redirect to verification page'
                                    ],
                                    Response::HTTP_OK
                                );
                            } else {
                                return response()->json(
                                    [
                                        'message' => 'Error To update to verification number'
                                    ],
                                    Response::HTTP_INTERNAL_SERVER_ERROR
                                );
                            }
                        } else {
                            return response()->json(
                                [
                                    'message' => 'Email already exist'
                                ],
                                Response::HTTP_UNPROCESSABLE_ENTITY
                            );
                        }

                        // Break the loop once a match is found
                        break;
                        // Else Not Exist Email then Create New User
                    } else {
                        $notExist = 1;
                    }
                } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
                    return response()->json(['message' => 'Error Decrypting Email'], Response::HTTP_INTERNAL_SERVER_ERROR);
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

            if ($notExist === 1) {
                if ($userCreate) {
                    // Get the Name of Gmail
                    $emailParts = explode('@', $email);
                    $name = [$emailParts[0]];

                    // Send to Email Now
                    Mail::to($email)->send(new VerificationMail($verificationNumber, $name));

                    // Set expiration time to 2 hours (120 minutes)
                    $expiration = Carbon::now()->addSeconds(1);
                    // Generate JWT token with a custom expiration time
                    $token = JWTAuth::fromUser($userCreate, ['exp' => $expiration->timestamp]);
                    return response()->json(
                        [
                            'token' => $token,
                            'message' => 'User created successfully'
                        ],
                        Response::HTTP_OK
                    );
                } else {
                    // Error creating user
                    return response()->json(['message' => 'Error creating user'], Response::HTTP_INTERNAL_SERVER_ERROR);
                }
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

    public function verifyEmail(Request $request)
    {
        $verificationNumber = mt_rand(100000, 999999);

        try {
            // Attempt to parse the token without authentication to check expiration
            $token = JWTAuth::parseToken();
            // Get the expiration time of the token
            $expiration = $token->getPayload()->get('exp');
            if (Carbon::now()->isAfter(Carbon::createFromTimestamp($expiration))) {
                return response()->json(['error' => 'Token expired. Please sign up again.'], Response::HTTP_UNAUTHORIZED);
            }

            // Authenticate the user with the provided token
            $user = $token->authenticate();
            // Check if the user is found
            if (!$user) {
                return response()->json(['error' => 'User not found'], Response::HTTP_NOT_FOUND);
            }

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
                    'email_verified_at' => now(),
                    'verification_number' => $verificationNumber,
                ]);

                return response()->json(['message' => 'Email verified successfully'], Response::HTTP_OK);
            }

            return response()->json(['error' => 'Invalid verification number'], Response::HTTP_NOT_FOUND);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            // Handle TokenExpiredException (e.g., token expired)
            return response()->json(['error' => 'Token expired. Please sign up again.'], Response::HTTP_UNAUTHORIZED);
        } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
            // Handle JWTException (e.g., token invalid)
            return response()->json(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }
    }

    
}
