<?php

namespace App\Http\Controllers;

use App\Models\AuthModel;
use Illuminate\Support\Str;
use App\Models\HistoryModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use App\Mail\VerificationMail;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class AccountController extends Controller
{
    protected $helper, $fillableAttrAuth;

    public function __construct(Helper $helper, AuthModel $fillableAttrAuth)
    {
        $this->helper = $helper;
        $this->fillableAttrAuth = $fillableAttrAuth;
    }

    // GET ALL USER ACCOUNT | ADMIN SIDE
    public function index(Request $request)
    {
        // Add action
        $crud_settings = $this->fillableAttrAuth->getApiAccountCrudSettings();
        $relative_settings = $this->fillableAttrAuth->getApiAccountRelativeSettings();
        $decrypted_auth_users = [];
        $column_name = [];
        $filter = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Unset Column not needed
        $unset_results = $this->helper->unsetColumn($this->fillableAttrAuth->unsetForRetrieves(), $this->fillableAttrAuth->getFillableAttributes());

        // Retrieve all AuthModel records
        $auth_users = AuthModel::get();

        // Data
        foreach ($auth_users as $auth_user) {
            $decrypted_auth_user = [];

            foreach ($unset_results as $column) {
                if ($column == 'user_id') {
                    $userInfo = UserInfoModel::where('user_id', $auth_user->user_id)->first();
                    $decrypted_auth_user['userInfo'] = [
                        'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                    ];
                    $decrypted_auth_user['id'] = Crypt::encrypt($auth_user->{$column});

                    // Add to column_name if it doesn't exist
                    if (!in_array($this->helper->transformColumnName('Id'), $column_name)) {
                        $column_name[] = $this->helper->transformColumnName('Id');
                    }
                } elseif ($column == 'email') {
                    $decrypted_auth_user[$column] = $auth_user->{$column} ? Crypt::decrypt($auth_user->{$column}) : null;
                    $history = HistoryModel::where('tbl_id', $auth_user->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
                    $decrypted_auth_user['password'] = $history ? Crypt::decrypt($history->value) : null;

                    // Add 'email' to column_name if it doesn't exist
                    if (!in_array($this->helper->transformColumnName($column), $column_name)) {
                        $column_name[] = $this->helper->transformColumnName($column);
                    }
                    // Add 'password' to column_name if it doesn't exist
                    if (!in_array('password', $column_name)) {
                        $column_name[] = 'password';
                    }
                } elseif ($column == 'role') {
                    // Add 'role' to column_name if it doesn't exist
                    if (!in_array($this->helper->transformColumnName($column), $column_name)) {
                        $column_name[] = $this->helper->transformColumnName($column);
                    }
                    foreach ($this->fillableAttrAuth->arrEnvRoles() as $roleEnv => $roleLabel) {
                        if ($auth_user->{$column} == env($roleEnv)) {
                            $decrypted_auth_user[$column] = $roleLabel;
                            break;
                        }
                    }
                } else {
                    // Add other columns to column_name if they don't exist
                    if (!in_array($this->helper->transformColumnName($column), $column_name)) {
                        $column_name[] = $this->helper->transformColumnName($column);
                    }
                    // Keep other columns as they are
                    $value = $auth_user->{$column};

                    // Check if the column needs formatting and value is not null
                    if (in_array($column, $this->fillableAttrAuth->arrHaveAtConvertToReadDateTime()) && $value !== null) {
                        // Format the value using Carbon
                        $carbon_date = Carbon::parse($value);
                        $value = $carbon_date->format('F j, Y g:i a');
                    }

                    // Assign the value to the decrypted_auth_user array
                    $decrypted_auth_user[$column] = $value;
                }
            }

            $crud_action = $this->helper->formatApi(
                $crud_settings['prefix'],
                $crud_settings['apiWithPayloads'],
                $crud_settings['methods'],
                $crud_settings['buttonNames'],
                $crud_settings['icons'],
                $crud_settings['actions']
            );

            // Unset button on action if exist the id on other tables
            $is_exist_id_other_tbl = $this->helper->isExistIdOtherTbl($auth_user->user_id, $this->fillableAttrAuth->arrModelWithId());
            if ($is_exist_id_other_tbl == 'exist') {
                foreach ($this->fillableAttrAuth->unsetActions() as $unsetAction) {
                    unset($crud_action[$unsetAction]);
                }
            }
            $decrypted_auth_user['action'] = [
                $crud_action
            ];

            // Add the decrypted user data to the array
            $decrypted_auth_users[] = $decrypted_auth_user;
        }

        // Column Name
        $column_name = array_map(function ($col) {
            return $this->helper->transformColumnName($col);
        }, $column_name);
        array_unshift($column_name, "User Info");
        $column_name[] = "Action";

        // Filter Column
        $filter_status = $this->helper->upperCaseValueSelectTagFilter($this->fillableAttrAuth->arrEnvAccountStatus());
        $filter_role = $this->helper->upperCaseValueSelectTagFilter($this->fillableAttrAuth->arrEnvAccountRole());
        $filter[] = [
            'status' => $filter_status,
            'role' => $filter_role
        ];

        // Final response structure
        $response = [
            'data' => $decrypted_auth_users,
            'column' => $column_name,
            'relative' => $this->helper->formatApi(
                $relative_settings['prefix'],
                $relative_settings['apiWithPayloads'],
                $relative_settings['methods'],
                $relative_settings['buttonNames'],
                $relative_settings['icons'],
                $relative_settings['actions']
            ),
            'filter' => $filter
        ];

        // Display or use the decrypted attributes as needed
        return response()->json(['messages' => [$response]], Response::HTTP_OK);
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
            return response()->json(['message' => 'Invalid I.D'], Response::HTTP_NOT_FOUND);
        }

        // Decrypt all emails and other attributes
        $decrypted_user_auth = [];
        $column_name = [];

        // Unset Column not needed
        $unset_results = $this->helper->unsetColumn($this->fillableAttrAuth->unsetForRetrieves(), $this->fillableAttrAuth->getFillableAttributes());

        // Retrieve AuthModel record
        $authUser = AuthModel::where('user_id', Crypt::decrypt($id))->first();

        if (!$authUser) {
            return response()->json(['message' => 'User not found'], Response::HTTP_NOT_FOUND);
        }

        foreach ($unset_results as $column) {
            if ($column == 'user_id') {
                $userInfo = UserInfoModel::where('user_id', $authUser->user_id)->first();
                $decrypted_user_auth['data']['userInfo'] = [
                    'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
                ];
                $decrypted_user_auth['data']['id'] = Crypt::encrypt($authUser->{$column});
                $column_name[] = $this->helper->transformColumnName('Id');
            } else if ($column == 'email') {
                $decrypted_user_auth['data'][$column] = $authUser->{$column} ? Crypt::decrypt($authUser->{$column}) : null;
                $history = HistoryModel::where('tbl_id', $authUser->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
                $decrypted_user_auth['data']['password'] = $history ? Crypt::decrypt($history->value) : null;
                $column_name[] = $this->helper->transformColumnName($column);
                $column_name[] = 'password';
            } else if ($column == 'role') {
                $column_name[] = $this->helper->transformColumnName($column);
                foreach ($this->fillableAttrAuth->arrEnvRoles() as $roleEnv => $roleLabel) {
                    if ($authUser->{$column} == env($roleEnv)) {
                        $decrypted_user_auth['data'][$column] = $roleLabel;
                        break;
                    }
                }
            } else {
                // Keep other columns as they are
                $column_name[] = $this->helper->transformColumnName($column);
                $value = $authUser->{$column};

                // Check if the column needs formatting and value is not null
                if (in_array($column, $this->fillableAttrAuth->arrHaveAtConvertToReadDateTime()) && $value !== null) {
                    // Format the value using Carbon
                    $carbonDate = Carbon::parse($value);
                    $value = $carbonDate->format('F j, Y g:i a');
                }

                // Assign the value to the decrypted_user_auth array
                $decrypted_user_auth['data'][$column] = $value;
            }
        }

        // Add new columns
        $new_columns = [
            "User Info",
            "Action"
        ];
        $transformedColumns = array_map(function ($column_name) {
            return $this->helper->transformColumnName($column_name);
        }, $column_name);
        array_unshift($transformedColumns, $this->helper->transformColumnName($new_columns[0]));
        array_push($transformedColumns, $this->helper->transformColumnName($new_columns[1]));

        // Display or use the decrypted attributes as needed
        return response()->json(['messages' => [$decrypted_user_auth]], Response::HTTP_OK);
    }

    // STORE USER ACCOUNT | ADMIN SIDE
    public function store(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);
        do {
            $user_id = Str::uuid()->toString();
        } while (AuthModel::where('user_id', $user_id)->exists());

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'phone_number' => $request->filled('phone_number') ? 'numeric|min:11' : 'nullable',
            'email' => $request->filled('email') ? 'required|string|max:255' : 'nullable',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'required|string|max:255',
            'status' => 'required|string|max:255',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device === 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $accounts = AuthModel::all();
        // Decrypt and validate email if exist
        foreach ($accounts as $account) {
            // Start Decrypt
            $decrypted_email = Crypt::decrypt($account->email);
            $decrypted_phone_number = Crypt::decrypt($account->email);

            if ($request->filled('phone_number')) {
                // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
                if ($decrypted_phone_number === $request->phone_number && $user->phone_verified_at !== null) {
                    return response()->json(
                        [
                            'message' => 'Phone number already exist'
                        ],
                        Response::HTTP_UNPROCESSABLE_ENTITY
                    );
                }
            }
            if ($request->filled('email')) {
                // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
                if ($decrypted_email === $request->email && $user->email_verified_at !== null) {
                    return response()->json(
                        [
                            'message' => 'Email already exist'
                        ],
                        Response::HTTP_UNPROCESSABLE_ENTITY
                    );
                }
            }
        }

        // Store only have value   
        foreach ($this->fillableAttrAuth->arrStoreFields() as $arrStoreField) {
            if ($arrStoreField == 'user_id') {
                $arr_validates[$arrStoreField] = $user_id;
            } else if ($arrStoreField == 'phone_number' && $request->filled('phone_number')) {
                $arr_validates[$arrStoreField] = Crypt::encrypt($request->phone_number);
            } else if ($arrStoreField == 'email' && $request->filled('email')) {
                $arr_validates[$arrStoreField] = Crypt::encrypt($request->email);
            } else if ($arrStoreField == 'password') {
                $arr_validates[$arrStoreField] = Hash::make($request->password);
            } else if ($arrStoreField == 'verification_number') {
                $arr_validates[$arrStoreField] = $verification_number;
            } else if ($arrStoreField == 'phone_verified_at' && $request->filled('phone_number')) {
                $arr_validates[$arrStoreField] = Carbon::now();
            } else if ($arrStoreField == 'email_verified_at' && $request->filled('email')) {
                $arr_validates[$arrStoreField] = Carbon::now();
            } else {
                $arr_validates[$arrStoreField] = $request->$arrStoreField;
            }
        }

        // Create the user
        $created = AuthModel::create($arr_validates);
        if (!$created) {
            return response()->json(['message' => 'Failed to store'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Format the logs
        $arr_log_details = ['fields' => []];
        foreach ($arr_validates as $field => $value) {
            // Only include non-null email and password for encryption
            if ($field === 'phone_number' || $field === 'email' || $field === 'password') {
                if ($value !== null) {
                    $arr_log_details['fields'][$field] = Crypt::encrypt($request->$field);
                }
            } else if ($field !== 'verification_number' && $field !== 'phone_verified_at' && $field !== 'email_verified_at') {
                // For other fields, include all values
                $arr_log_details['fields'][$field] = $value;
            }
        }

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $request->eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 1,
            'is_history' => 1,
            'log_details' => $arr_log_details,
            'user_action' => 'STORE USER ACCOUNT',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Successfully created user',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }


    // UPDATE USER ACCOUNT | ADMIN SIDE
    public function update(Request $request)
    {
        $arr_log_details = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|string',
            'phone_number' => $request->filled('phone_number') ? 'numeric|min:11' : 'nullable',
            'email' => $request->filled('email') ? 'required|string|max:255' : 'nullable',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'required|string|max:255',
            'status' => 'required|string|max:255',
            'eu_device' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_BAD_REQUEST);
        }

        // Validate eu_device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device === 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $account = AuthModel::where('user_id', Crypt::decrypt($request->user_id))->first();
        // Check if inventory record exists
        if (!$account) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        $history = HistoryModel::where('tbl_id', $account->user_id)->where('tbl_name', 'users_tbl')->where('column_name', 'password')->latest()->first();
        if (!$history) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        // Validate if exist phone number or email
        if ($request->filled('phone_number')) {

            $decrypted_phone_number = Crypt::decrypt($account->email);
            // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
            if ($decrypted_phone_number === $request->phone_number && $user->phone_number_verified_at !== null) {
                return response()->json(
                    [
                        'message' => 'Phone number already exist'
                    ],
                    Response::HTTP_UNPROCESSABLE_ENTITY
                );
            }
        }
        if ($request->filled('email')) {
            $decrypted_email = Crypt::decrypt($account->email);

            // Check if the requested email exists in the decrypted emails and email_verified_at is null then send verification code
            if ($decrypted_email === $request->email && $user->email_verified_at !== null) {
                return response()->json(
                    [
                        'message' => 'Email already exist'
                    ],
                    Response::HTTP_UNPROCESSABLE_ENTITY
                );
            }
        }


        // Put on logs not equal value then put on update
        foreach ($this->fillableAttrAuth->arrUpdateFields() as $arrUpdateFields) {
            if ($arrUpdateFields == 'phone_number') {
                if ($request->filled('phone_number')) {
                    $existing_value = $account->$arrUpdateFields != '' ? Crypt::decrypt($account->$arrUpdateFields) : null;
                    $new_value = $request->arrUpdateFields ?? null;
                    // Check if the value has changed
                    if ($existing_value !== $new_value) {

                        $changes_for_logs[$arrUpdateFields] = [
                            'old' => Crypt::encrypt($existing_value),
                            'new' => Crypt::encrypt($new_value),
                        ];

                        $arr_validates[$arrUpdateFields] = Crypt::encrypt($request->phone_number);
                    }
                }
            } else if ($arrUpdateFields == 'email') {
                if ($request->filled('email')) {
                    $existing_value = $account->$arrUpdateFields != '' ? Crypt::decrypt($account->$arrUpdateFields) : null;
                    $new_value = $request->$arrUpdateFields != '' ? $request->$arrUpdateFields : null;

                    // Check if the value has changed
                    if ($existing_value !== $new_value) {
                        $changes_for_logs[$arrUpdateFields] = [
                            'old' => Crypt::encrypt($existing_value),
                            'new' => Crypt::encrypt($new_value),
                        ];
                        $arr_validates[$arrUpdateFields] = Crypt::encrypt($request->email);
                    }
                }
            } else if ($arrUpdateFields == 'password') {
                $existing_value = $account->$arrUpdateFields != '' ? $account->$arrUpdateFields : null;
                $new_value = $request->$arrUpdateFields != '' ? $request->$arrUpdateFields : null;

                // Check if the value has changed
                if (!Hash::check($new_value, $existing_value)) {
                    $changes_for_logs[$arrUpdateFields] = [
                        'old' => $history->value,
                        'new' => Crypt::encrypt($new_value),
                    ];
                    $arr_validates[$arrUpdateFields] = Hash::make($new_value);
                }
            } else {
                $existing_value = $account->$arrUpdateFields != '' ? $account->$arrUpdateFields : null;
                $new_value = $request->$arrUpdateFields != '' ? $request->$arrUpdateFields : null;

                // Check if the value has changed
                if ($existing_value !== $new_value) {
                    $changes_for_logs[$arrUpdateFields] = [
                        'old' => $existing_value,
                        'new' => $new_value,
                    ];
                }
                $arr_validates[$arrUpdateFields] = $request->$arrUpdateFields;
            }
        }

        // Update the user
        $update = $account->update($arr_validates);
        if (!$update) {
            return response()->json(['message' => 'Failed to store'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Format the logs
        $arr_log_details['fields']['user_id'] = $account->user_id;
        $arr_log_details['fields'] = array_merge($arr_log_details['fields'], $changes_for_logs);

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $request->eu_device,
            'user_id' => $account->user_id,
            'is_sensitive' => 1,
            'is_history' => 1,
            'log_details' => $arr_log_details,
            'user_action' => 'UPDATE USER ACCOUNT',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'Successfully update user account',
            'log_message' => $log_result
        ], Response::HTTP_CREATED);
    }


    /**
     * UPDATE EMAIL | CLIENT SIDE
     * Update email
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function updateEmailOnSettingUser(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);

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
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device == 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $user_auth = AuthModel::where('user_id', $user->user_id)->first();
        if (!$user_auth) {
            return response()->json(['message' => 'Intruder'], Response::HTTP_NOT_FOUND);
        }

        if (Crypt::decrypt($user_auth->email) == $request->new_email) {
            return response()->json(['message' => 'The new email cannot be the same as the old email. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($user_auth->email) != $request->new_email && !Hash::check($request->input('current_password'), $user_auth->password)) {
            return response()->json(['message' => 'Incorrect password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (Crypt::decrypt($user_auth->email) != $request->new_email && Hash::check($request->input('current_password'), $user_auth->password) && $user_auth->verification_number != $request->verification_number) {
            return response()->json(['message' => 'Incorrect verification number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Update the user's email
            $user_auth->email = Crypt::encrypt($request->new_email);
            $user_auth->verification_number = $verification_number;

            // Saving
            if (!$user_auth->save()) {
                return response()->json(['message' => 'Failed to update email'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Log details
            $arr_log_details = [
                'fields' => [
                    'user_id' => $user->user_id,
                    'old_email' => $user->email,
                    'new_email' => Crypt::encrypt($request->new_email),
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 1,
                'is_history' => 0,
                'log_details' => $arr_log_details,
                'user_action' => 'UPDATE EMAIL ON SETTINGS OF USER',
            ];


            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);

            return response()->json([
                'message' => 'Email updated successfully',
                'log_message' => $log_result,
            ], Response::HTTP_OK);
        }
    }

    /**
     * UPDATE PASSWORD | CLIENT SIDE
     * Update password
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function updatePasswordOnSettingUser(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);

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
            'eu_device' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device == 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Fetch the user from the database
        $user_auth = AuthModel::where('user_id', $user->user_id)->first();
        // Check if user exists
        if (!$user_auth) {
            return response()->json(['message' => 'Intruder'], Response::HTTP_NOT_FOUND);
        }

        if (Hash::check($request->input('password'), $user_auth->password)) {
            return response()->json(['message' => 'The new password cannot be the same as the old password. Please choose a different one'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if (!Hash::check($request->input('current_password'), $user_auth->password)) {
            return response()->json(['message' => 'Incorrect current password'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else if ($user_auth->verification_number != $request->input('verification_number')) {
            return response()->json(['message' => 'Incorrect Verification Number'], Response::HTTP_UNPROCESSABLE_ENTITY);
        } else {
            // Update the user's password
            $user_auth->password =  Hash::make($request->input('password'));
            $user_auth->verification_number = $verification_number;

            // Saving
            if (!$user_auth->save()) {
                return response()->json(['message' => 'Failed to update new password'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Log details
            $arr_log_details = [
                'fields' => [
                    'user_id' => $user->user_id,
                    'old' => Crypt::encrypt($request->input('current_password')),
                    'new' => Crypt::encrypt($request->input('password')),
                ]
            ];

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $request->eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 1,
                'is_history' => 1,
                'log_details' => $arr_log_details,
                'user_action' => 'UPDATE PASSWORD ON USER SETTING',
            ];


            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);

            return response()->json([
                'message' => 'Password updated successfully',
                'log_message' => $log_result
            ], Response::HTTP_OK);
        }
    }

    /**
     * CHILD updatePasswordOnSettingUser | CLIENT SIDE
     * Resend code password
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function resendVerificationCodeEmail(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->helper->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate
        $validator = Validator::make($request->all(), [
            'eu_device' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device == 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $update_user_verification_number = $user->update([
            'verification_number' => $verification_number,
        ]);

        if (!$update_user_verification_number) {
            return response()->json([
                'message' => 'Failed to generate verification number',
            ], Response::HTTP_OK);
        }

        $email_parts = explode('@', Crypt::decrypt($user->email));
        $name = [$email_parts[0]];

        $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verification_number, $name));
        if (!$email) {
            return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $arr_log_details = [
            'fields' => [
                'user_id' => $user->user_id,
                'verification_number' => $user->verification_number
            ]
        ];

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $request->eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $arr_log_details,
            'user_action' => 'RESEND NEW VERIFICATION CODE UPON USER SETTINGS EMAIL UPDATE',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'A new verification code has been sent to your email',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }

    /**
     * CHILD updateEmailOnSettingUser | CLIENT SIDE
     * Resend code email
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function resendVerificationCodePassword(Request $request)
    {
        $verification_number = mt_rand(100000, 999999);

        // Authorize the user
        $user = $this->helper->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validate
        $validator = Validator::make($request->all(), [
            'eu_device' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json(['message' => $validator->errors()], Response::HTTP_NOT_FOUND);
        }

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device == 'invalid') {
            return response()->json(['message' => 'Incorrect eu_device'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $update_user_verification_number = $user->update([
            'verification_number' => $verification_number,
        ]);

        if (!$update_user_verification_number) {
            return response()->json([
                'message' => 'Failed to generate verification number',
            ], Response::HTTP_OK);
        }

        $email_parts = explode('@', Crypt::decrypt($user->email));
        $name = [$email_parts[0]];

        $email =  Mail::to(Crypt::decrypt($user->email))->send(new VerificationMail($verification_number, $name));
        if (!$email) {
            return response()->json(['message' => 'Failed to send the verification number to your email'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $arr_log_details = [
            'fields' => [
                'user_id' => $user->user_id,
                'verification_number' => $user->verification_number
            ]
        ];

        // Arr Data Logs
        $arr_data_logs = [
            'user_device' => $request->eu_device,
            'user_id' => $user->user_id,
            'is_sensitive' => 0,
            'is_history' => 0,
            'log_details' => $arr_log_details,
            'user_action' => 'RESEND NEW VERIFICATION CODE UPON USER SETTINGS PASSWORD UPDATE',
        ];

        // Logs
        $log_result = $this->helper->log($request, $arr_data_logs);

        return response()->json([
            'message' => 'A new verification code has been sent to your email',
            'log_message' => $log_result
        ], Response::HTTP_OK);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }
}
