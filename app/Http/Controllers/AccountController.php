<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AccountController extends Controller
{

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }


    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
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
}
