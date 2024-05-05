<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    protected $helper, $fillableAttrLogs;

    public function __construct(Helper $helper, LogsModel $fillableAttrLogs)
    {
        $this->fillableAttrLogs = $fillableAttrLogs;
        $this->helper = $helper;
    }

    public function index(Request $request)
    {
        $decrypted_logs = [];
        $result_json = [];
        $arr_with_parent_id = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $logs = LogsModel::get();

        foreach ($logs as $log) {
            $details_json = json_decode($log['details'], true);

            // Decrypt the data
            $decrypted_data = $this->isDecryptedData($log->is_sensitive, ($details_json['fields'] ?? $details_json), $this->fillableAttrLogs->encryptedFields(), $this->fillableAttrLogs->notToDecrypt());

            // Decrypted data save on fields
            $arr_with_parent_id = [
                'fields' => $decrypted_data
            ];

            foreach ($this->fillableAttrLogs->getFillableAttributes() as $fillableAttrLog) {
                if ($fillableAttrLog == 'details') {
                    $decrypted_logs[$fillableAttrLog] = $arr_with_parent_id;
                } else if ($fillableAttrLog == 'user_device') {
                    $decrypted_logs[$fillableAttrLog] = json_decode($log->$fillableAttrLog, true);
                } else {
                    $decrypted_logs[$fillableAttrLog] = $log->$fillableAttrLog;
                }
            }

            // Retrieve userInfo model
            $user_info = UserInfoModel::where('user_id', $log['user_id'])->first();
            if ($user_info) {
                $arr_user_info = $user_info->toArray();

                foreach ($this->fillableAttrLogs->encryptedFields() as $encryptedField) {
                    if (isset($arr_user_info[$encryptedField])) {
                        $arr_user_info[$encryptedField] = $user_info->{$encryptedField} ? Crypt::decrypt($user_info->{$encryptedField}) : null;
                    }
                }
                $decrypted_logs['userInfo'] = $arr_user_info;
            } else {
                $decrypted_logs['userInfo'] = [];
            }
            $result_json[] = $decrypted_logs;
        }

        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $result_json,
        ], Response::HTTP_OK);
    }

    // HELPER FUNCTION
    public function isDecryptedData($is_sensitive, $fields, $fields_to_decrypt, $not_to_decrypts)
    {
        $decrypted_data = [];

        // Iterate over each field in the log details
        foreach ($fields as $field_name => $field_value) {
            foreach ($not_to_decrypts as $not_to_decrypt) {
                if ($not_to_decrypt != $field_name) {
                    // Check if the field is sensitive and needs decryption
                    if ($is_sensitive == 1 && in_array($field_name, $fields_to_decrypt)) {
                        if (is_array($field_value)) {
                            $decOld = isset($field_value['oldEnc']) ? Crypt::decrypt($field_value['oldEnc']) : (isset($field_value['old']) ? Crypt::decrypt($field_value['old']) : null);
                            $decNew = isset($field_value['newEnc']) ? Crypt::decrypt($field_value['newEnc']) : (isset($field_value['new']) ? Crypt::decrypt($field_value['new']) : null);

                            $decrypted_data[$field_name]['old'] = $decOld;
                            $decrypted_data[$field_name]['new'] = $decNew;
                        } else {
                            $decrypted_data[$field_name] = $field_value !== null ? Crypt::decrypt($field_value) : null;
                        }
                    } else {
                        $decrypted_data[$field_name] = $field_value;
                    }
                } else {
                    // Field is not sensitive or does not need decryption
                    $decrypted_data[$field_name] = $field_value;
                }
            }
        }

        Log::info($decrypted_data);


        return $decrypted_data;
    }
}
