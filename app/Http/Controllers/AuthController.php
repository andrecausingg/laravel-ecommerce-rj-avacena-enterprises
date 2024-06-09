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
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;

use App\Mail\ResendVerificationMail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    protected $helper;

    public function __construct(Helper $helper)
    {
        $this->helper = $helper;
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

    public function checkToken(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        return response()->json([
            'access_token' => $user->session_token,
        ], Response::HTTP_OK);
    }

    public function roleNavLinks(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $nav_links_admin = [
            [
                'title' => 'Menu',
                'path' => '/menu',
                'icon' => 'heroicons-outline:view-grid',
                'path_key' => 'inventory/parent/index'
            ],
            [
                'title' => 'Dashboard',
                'path' => '/dashboard',
                'icon' => 'heroicons-outline:chart-pie',
                'path_key' => 'payment/dashboard'
            ],
            [
                'title' => 'Inventory',
                'path' => '/inventory',
                'icon' => 'heroicons-outline:cube',
                'path_key' => 'inventory/parent/index'
            ],
            [
                'title' => 'Users',
                'path' => '/users',
                'icon' => 'heroicons-outline:user-group',
                'path_key' => 'admin-accounts/index'
            ],
            [
                'title' => 'Orders',
                'icon' => 'heroicons-outline:clipboard-list',
                'submenus' => [
                    [
                        'title' => 'Customer Order',
                        'path' => '/customer-order',
                        'icon' => 'heroicons-outline:user-group',
                    ],
                    [
                        'title' => 'Return Order',
                        'path' => '/return-order',
                        'icon' => 'heroicons-outline:user-group',
                    ],
                    [
                        'title' => 'Failed Delivery',
                        'path' => '/failed-delivery',
                        'icon' => 'heroicons-outline:user-group',
                    ],
                    [
                        'title' => 'Cancellation',
                        'path' => '/cancellation',
                        'icon' => 'heroicons-outline:user-group',
                    ],
                ],
            ],
        ];

        if ($user->role === env('ROLE_SUPER_ADMIN')) {
            return response()->json([
                'nav_links' => $nav_links_admin,
            ], Response::HTTP_OK);
        } else {
            return response()->json([
                'message' => 'Invalid role',
            ], Response::HTTP_OK);
        }
    }

    public function logout(Request $request)
    {
        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->input('eu_device'));
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        DB::beginTransaction();

        try {
            // Expiration Time 1month
            $expiration_time = Carbon::now()->addSeconds(1);
            $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);
            if (!$new_token) {
                return response()->json([
                    'message' => 'Unable to generate a token from user'
                ], Response::HTTP_OK);
            }

            $user->session_token = $new_token;
            $user->session_expire_at = $expiration_time;

            if (!$user->save()) {
                return response()->json(
                    ['message' => 'Failed to update session token and expiration'],
                    Response::HTTP_INTERNAL_SERVER_ERROR
                );
            }

            // Arr Logs details
            $arr_log_details = [
                'fields' => [
                    'user_id' => $user->user_id,
                    'ip_address' => $request->ip(),
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->input('eu_device'),
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'LOGOUT',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);

            DB::commit();

            return response()->json([
                'message' => 'User logout successfully',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json(['message' => 'Failed to store inventory records', 'error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * PARENT LOGIN
     * Login
     *
     * @param  \Illuminate\Http\Request  $request
     */
    public function login(Request $request)
    {
        $arr_data = [];

        // Check if phone number is not empty
        if ($request->has('phone_number') && ($request->input('phone_number') !== '' || $request->input('phone_number') !== null)) {
            $validator = Validator::make($request->all(), [
                'phone_number' => 'required|numeric',
                'password' => 'required|string',
            ]);

            $arr_data['phone_number'] = $request->phone_number;
            $arr_data['password'] = $request->password;

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()],  Response::HTTP_UNPROCESSABLE_ENTITY);
            }
        }
        // Check if Email is not empty
        else if ($request->has('email') && ($request->input('email') !== '' || $request->input('email') !== null)) {
            // Validate Password
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string',
                'eu_device' => 'required|string',
            ]);

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
            }

            // Validate Eu Device
            $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }

            $arr_data['email'] = $request->email;
            $arr_data['password'] = $request->password;
            $arr_data['eu_device'] = $request->eu_device;

            return $this->loginEmail($request, $arr_data);
        }
    }

    /**
     * CHILD LOGIN
     * Login
     *
     * @param array $arr_data
     * @return \Illuminate\Http\JsonResponse
     */
    public function loginEmail($request, $arr_data)
    {
        $verification_number = mt_rand(100000, 999999);

        // Decrypt al email first
        $users = AuthModel::all();

        foreach ($users as $user) {
            $decrypted_email = Crypt::decrypt($user->email);

            // Check if Verified Email
            if ($decrypted_email == $arr_data['email'] && Hash::check($arr_data['password'], $user->password) && $user->email_verified_at !== null) {
                // $expirationTime = Carbon::now()->addSeconds(30);
                // Expiration Time 1month
                $expiration_time = Carbon::now()->addMinutes(2592000);
                $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);
                if (!$new_token) {
                    return response()->json([
                        'message' => 'Unable to generate a token from user'
                    ], Response::HTTP_OK);
                }

                $user->session_token = $new_token;
                $user->session_expire_at = $expiration_time;

                if (!$user->save()) {
                    return response()->json(
                        ['message' => 'Failed to update session token and expiration'],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Check If users_info_tbl exist 
                $user_info_exist = UserInfoModel::where('user_id', $user->user_id)
                    ->where(function ($query) {
                        $query->whereNull('first_name')->orWhere('first_name', '');
                        $query->orWhereNull('last_name')->orWhere('last_name', '');
                    })
                    ->exists();

                // Arr Logs details
                $arr_log_details = [
                    'fields' => [
                        'user_id' => $user->user_id,
                        'ip_address' => $request->ip(),
                    ]
                ];

                // Arr Data Logs
                $arr_data_logs = [
                    'user_device' => $arr_data['eu_device'],
                    'user_id' => $user->user_id,
                    'is_sensitive' => 0,
                    'is_history' => 0,
                    'log_details' => $arr_log_details,
                    'user_action' => 'LOGIN',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);

                return response()->json([
                    // 'user' => $user,
                    'user_info' => $user_info_exist ? 'Existing User' : 'New User',
                    'token_type' => 'Bearer',
                    'access_token' => $new_token,
                    'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
                    'message' => 'Login Successfully',
                    'log_message' => $log_result
                ], Response::HTTP_OK);
            }
            // Check if Not Verified then redirect to Verify Email
            else if ($decrypted_email == $arr_data['email'] && Hash::check($arr_data['password'], $user->password) && $user->email_verified_at === null) {
                // Generate a new token for the user
                $expiration_time = Carbon::now()->addMinutes(120);
                $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);

                if (!$new_token) {
                    return response()->json([
                        'message' => 'Failed to generate a token from user'
                    ], Response::HTTP_OK);
                }

                // Update verification_number | password | verify email token
                $user->verification_number = $verification_number;
                $user->verify_email_token = $new_token;
                $user->verify_email_token_expire_at = $expiration_time;

                // Save
                if (!$user->save()) {
                    return response()->json(
                        [
                            'message' => 'Failed To update to verification number, token and expiration time'
                        ],
                        Response::HTTP_INTERNAL_SERVER_ERROR
                    );
                }

                // Arr Logs details
                $arr_log_details = [
                    'fields' => [
                        'user_id' => $user->user_id,
                        'ip_address' => $request->ip(),
                    ]
                ];

                // Arr Data Logs
                $arr_data_logs = [
                    'user_device' => $arr_data['eu_device'],
                    'user_id' => $user->user_id,
                    'is_sensitive' => 0,
                    'is_history' => 0,
                    'log_details' => $arr_log_details,
                    'user_action' => 'USER ATTEMPTED TO LOG IN BUT HAS NOT YET BEEN VERIFIED. REDIRECTING TO VERIFY EMAIL',
                ];

                // Logs
                $log_result = $this->helper->log($request, $arr_data_logs);

                // Get the Name of Gmail
                $emailParts = explode('@', $decrypted_email);
                $name = [$emailParts[0]];

                // Send the new token to the user via email
                Mail::to($decrypted_email)->send(new VerificationMail($verification_number, $name));

                return response()->json(
                    [
                        'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
                        'message' => '/signup/verify-email?tj=' . $new_token,
                    ],
                    Response::HTTP_OK
                );
            }
        }

        return response()->json([
            'message' => 'Invalid credential'
        ], Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    /**
     * PARENT REGISTER
     * Register a new user.
     *
     * @param  \Illuminate\Http\Request  $request
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
        if ($request->has('phone_number') && ($request->input('phone_number') !== '' || $request->input('phone_number') !== null)) {
            $validator = Validator::make($request->all(), [
                'phone_number' => 'required|numeric',
                'password' => 'required|string|min:8|confirmed:password_confirmation',
                'eu_device' => 'required|string',
            ]);

            $arr_data['phone_number'] = $request->phone_number;
            $arr_data['password'] = $request->password;

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()],  Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }
        }
        // Check if Email is not empty
        else if ($request->has('email') && ($request->input('email') !== '' || $request->input('email') !== null)) {
            // Validate Password
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:8|confirmed:password_confirmation',
                'eu_device' => 'required|string',
            ]);

            if ($validator->fails()) {
                return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
            }

            $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
            if ($result_validate_eu_device) {
                return $result_validate_eu_device;
            }

            $arr_data['email'] = $request->email;
            $arr_data['password'] = $request->password;
            $arr_data['eu_device'] = $request->eu_device;

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
        // Begin a transaction
        DB::beginTransaction();

        try {
            // Generate a new token for the user
            $expiration_time = Carbon::now()->addMinutes(5);
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
                        // Rollback the transaction
                        DB::rollBack();

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
                        // Rollback the transaction
                        DB::rollBack();

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
                        'user_device' => $arr_data['eu_device'],
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
                        // Rollback the transaction
                        DB::rollBack();

                        return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
                    }

                    // Commit the transaction
                    DB::commit();

                    return response()->json([
                        'message' => 'Successfully register email',
                        'url_token' => '/signup/verify-email?tj=' . $new_token,
                        'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
                        'log_message' => $log_result
                    ], Response::HTTP_OK);
                }

                // If same email exist and email_verified_at not null send error message
                else if ($decrypted_email === $arr_data['email'] && $user->email_verified_at !== null) {
                    // Rollback the transaction
                    DB::rollBack();

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
                // Rollback the transaction
                DB::rollBack();

                return response()->json(['message' => 'Failed to create user'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user_create);

            if (!$new_token) {
                // Rollback the transaction
                DB::rollBack();

                return response()->json(['message' => 'Failed to generate token'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Update user with the new token for email verification
            $user_create->verify_email_token = $new_token;
            $user_create->verify_email_token_expire_at = $expiration_time;

            if (!$user_create->save()) {
                // Rollback the transaction
                DB::rollBack();

                return response()->json(['message' => 'Failed to update token and expire at'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Arr Logs details
            $arr_log_details = [
                'fields' => [
                    'user_id' => $arr_data['user_id'],
                    'email' => Crypt::encrypt($arr_data['email']),
                    'password' => [
                        'new' => Crypt::encrypt($arr_data['password']),
                    ]
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $arr_data['eu_device'],
                'user_id' => $arr_data['user_id'],
                'is_sensitive' => 1,
                'is_history' => 1,
                'log_details' => $arr_log_details,
                'user_action' => 'REGISTER AN ACCOUNT USING EMAIL',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Get the Name of Gmail
            $emailParts = explode('@', $arr_data['email']);
            $name = $emailParts[0];

            // Send an email to the user with the new token
            $email = Mail::to($arr_data['email'])->send(new VerificationMail($arr_data['verification_number'], $name));
            if (!$email) {
                // Rollback the transaction
                DB::rollBack();

                return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'Successfully register email',
                'url_token' => '/signup/verify-email?tj=' . $new_token,
                'expire_at' => $expiration_time->diffInSeconds(Carbon::now()),
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => 'An error occurred during the registration process', 'error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    /**
     * CHILD EMAIL REGISTER
     * Verify email
     *
     * @param  \Illuminate\Http\Request  $request
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
            'eu_device' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        // Begin a transaction
        DB::beginTransaction();

        try {
            // Check if the provided verification number matches the stored one
            if ($user->verification_number != $request->verification_number) {
                // Rollback the transaction
                DB::rollBack();

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
                // Rollback the transaction
                DB::rollBack();

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
                    'email_verified_at' =>  Carbon::parse($user->email_verified_at)->format("F j, Y g:i a"),
                    'verification_number' => $request->verification_number,
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $log_details,
                'user_action' => 'SUCCESS VERIFY EMAIL',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json(
                [
                    'message' => 'Email verified successfully',
                    'log_message' => $log_result
                ],
                Response::HTTP_OK
            );
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();

            return response()->json(
                [
                    'message' => 'An error occurred during the verification process',
                    'error' => $e->getMessage()
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }


    /**
     * SIGN UP | VERIFY EMAIL RESEND CODE
     * Resend Code
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function resendVerificationAuth(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);


        // Authorize the user
        $user = $this->authorizeUserResendCode($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate
        $validator = Validator::make($request->all(), [
            'eu_device' => 'required|string',
        ]);
        if ($validator->fails()) {
            // Rollback the transaction
            DB::rollBack();
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            // Rollback the transaction
            DB::rollBack();
            return $result_validate_eu_device;
        }

        // Begin a transaction
        DB::beginTransaction();

        try {
            // Log Details
            $log_details = [
                'fields' => [
                    'user_id' => $user->user_id,
                    'old_verification_number' => $user->verification_number,
                ]
            ];

            // Update user's verification number
            $update_user_verification_number = $user->update([
                'verification_number' => $verification_number,
            ]);

            if (!$update_user_verification_number) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json([
                    'message' => 'Failed to generate verification number',
                ], Response::HTTP_OK);
            }

            // Get user's email
            $userEmail = Crypt::decrypt($user->email);
            $email_parts = explode('@', $userEmail);
            $name = [$email_parts[0]];

            // Send email with the new verification code
            $email =  Mail::to($userEmail)->send(new VerificationMail($verification_number, $name));
            if (!$email) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Log Details
            $log_details['fields']['new_verification_number'] = $verification_number;

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $log_details,
                'user_action' => 'RESEND NEW VERIFICATION CODE AT VERIFY EMAIL',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'A new verification code has been sent to your email',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => 'An error occurred during the process', 'error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    /**
     * SIGN UP | VERIFY EMAIL RESEND CODE
     * Resend Code
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function forgotPassword(Request $request)
    {
        // Validate
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            // Rollback the transaction
            DB::rollBack();
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            // Rollback the transaction
            DB::rollBack();
            return $result_validate_eu_device;
        }


        // Begin a transaction
        DB::beginTransaction();

        try {
            // Get All Users and Decrypt
            $users = AuthModel::all();

            // Decrypt
            foreach ($users as $user) {
                // Start Decrypt
                $decrypted_email = Crypt::decrypt($user->email);

                // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
                if ($decrypted_email === $request->email && $user->email_verified_at !== null) {
                    // 2hrs expiration to verified Email
                    $expiration_time = Carbon::now()->addMinutes(5);
                    $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);

                    // Update token and expiration
                    $user->reset_password_token = $new_token;
                    $user->reset_password_token_expire_at = $expiration_time;

                    // Save
                    if (!$user->save()) {
                        // Rollback the transaction
                        DB::rollBack();
                        return response()->json(['message' => 'Failed to save token and expiration'], Response::HTTP_INTERNAL_SERVER_ERROR);
                    }

                    // Send to Email Now
                    $mail = Mail::to($request->email)->send(new ResetPasswordMail($new_token, $request->email, $expiration_time));
                    if (!$mail) {
                        // Rollback the transaction
                        DB::rollBack();
                        return response()->json(['message' => 'Failed to send reset password link on your email'], Response::HTTP_OK);
                    }

                    $log_details = [
                        'fields' => [
                            'user_id' => $user->user_id,
                            'email' => Crypt::encrypt($request->email),
                        ]
                    ];

                    // Arr Data Logs
                    $arr_data_logs = [
                        'user_device' => $request->eu_device,
                        'user_id' => $user->user_id,
                        'is_sensitive' => 1,
                        'is_history' => 0,
                        'log_details' => $log_details,
                        'user_action' => 'SUCCESSFULLY SENT RESET LINK FOR PASSWORD UPDATE',
                    ];

                    // Logs
                    $log_result = $this->helper->log($request, $arr_data_logs);
                    if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                        DB::rollBack();
                        return $log_result;
                    }

                    // Commit the transaction
                    DB::commit();

                    return response()->json([
                        'message' => 'Successfully sent a reset password link to your email ' . $decrypted_email,
                        'log_message' => $log_result
                    ], Response::HTTP_OK);
                }
                // If same email exist and email_verified_at equal null send error message
                else if ($decrypted_email === $request->email && $user->email_verified_at === null) {
                    // Rollback the transaction
                    DB::rollBack();
                    return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
                }
            }

            // Rollback the transaction
            DB::rollBack();
            return response()->json(['message' => 'Email not found or not verified'], Response::HTTP_NOT_FOUND);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => 'An error occurred during the process', 'error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    /**
     * FORGOT PASSWORD | UPDATE PASSWORD
     * Update Password
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function updatePassword(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUserUpdatePassword($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate Password
        $validator = Validator::make($request->all(), [
            'password' => 'required|string|min:6|confirmed',
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            // Return the validation errors
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }


        // Begin a transaction
        DB::beginTransaction();

        try {
            // Fetch the user from the database
            $user_auth = AuthModel::where('user_id', $user->user_id)->first();

            // Check if user exists
            if (!$user_auth) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            if (Hash::check($request->input('password'), $user_auth->password)) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $history = HistoryModel::where('tbl_id', $user_auth->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
            if (!$history) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }


            // Expiration to verified Email
            $expiration_time = Carbon::now()->addSecond();
            $new_token = JWTAuth::claims(['exp' => $expiration_time->timestamp])->fromUser($user);

            // Update the user's password
            $user_auth->password =  Hash::make($request->input('password'));
            $user_auth->reset_password_token =  $new_token;
            $user_auth->reset_password_token_expire_at =  $expiration_time;

            // Saving
            if (!$user_auth->save()) {
                // Rollback the transaction
                DB::rollBack();
                return response()->json(['message' => 'Failed to update new password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $log_details = [
                'fields' => [
                    'user_id' => $user->user_id,
                    'password' => [
                        'old' => $history->value,
                        'new' => Crypt::encrypt($request->input('password')),
                    ]
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 1,
                'is_history' => 1,
                'log_details' => $log_details,
                'user_action' => 'UPDATE PASSWORD ON FORGOT PASSWORD',
            ];


            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json([
                'message' => 'Password updated successfully',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction on any exception
            DB::rollBack();
            return response()->json(['message' => 'An error occurred during the process', 'error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    /**
     * AUTHENTICATE TOKEN
     * Auth Verify email
     *
     * @param  $request
     * @return \Illuminate\Http\JsonResponse
     */
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

    /**
     * AUTHENTICATE TOKEN
     * This resend code
     *
     * @param  $request
     * @return \Illuminate\Http\JsonResponse
     */
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

    /**
     * AUTHENTICATE TOKEN
     * Update Password
     *
     * @param  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function authorizeUserUpdatePassword($request)
    {
        try {
            // Authenticate the user with the provided token
            $user = JWTAuth::parseToken()->authenticate();
            // Get the bearer token from the headers
            $bearer_token = $request->bearerToken();

            // Check if user is not found
            if (!$user) {
                return response()->json(['message' => 'User not found'], Response::HTTP_UNAUTHORIZED);
            }

            // Check if bearer token is missing
            if ($user->reset_password_token !== $bearer_token) {
                return response()->json(['message' => 'Invalid token'], Response::HTTP_UNAUTHORIZED);
            }

            // Check if the user's session token does not match the bearer token or if the session has expired
            if ($user->reset_password_token_expire_at < Carbon::now()) {
                return response()->json(['message' => 'Session Expired'], Response::HTTP_UNAUTHORIZED);
            }

            // If everything is valid, return the authenticated user
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
