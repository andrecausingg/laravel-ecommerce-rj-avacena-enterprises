<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    protected $encryptedFields, $fillableAttributes, $notToDecrypt, $helper;

    public function __construct(Helper $helper)
    {

        $logsModel = new LogsModel();

        $this->encryptedFields = config('system.logs.EncryptedFields');
        $this->notToDecrypt = config('system.logs.NotToDecrypt');
        $this->fillableAttributes = $logsModel->getFillableAttributes();
        $this->helper = $helper;
    }

    public function index(Request $request)
    {
        $decryptedLogs = [];
        $resultJson = [];

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $logs = LogsModel::get();

        foreach ($logs as $log) {
            $detailsJson = json_decode($log['details'], true);

            if (isset($detailsJson['fields'])) {
                // Decrypt the data
                $decryptedData = $this->isDecryptedData($log->is_sensitive, $detailsJson['fields'], $this->encryptedFields, $this->notToDecrypt);
                
                // Decrypted data save on fields
                $arrWithParentId = [
                    'fields' => $decryptedData
                ];
            }

            foreach ($this->fillableAttributes as $fillableAttribute) {
                if ($fillableAttribute == 'details') {
                    $decryptedLogs[$fillableAttribute] = $arrWithParentId;
                }else if($fillableAttribute == 'user_device'){
                    $decryptedLogs[$fillableAttribute] = json_decode($log->$fillableAttribute, true);
                } else {
                    $decryptedLogs[$fillableAttribute] = $log->$fillableAttribute;
                }
            }

            // Retrieve userInfo model
            $userInfo = UserInfoModel::where('user_id', $log['user_id'])->first();
            if ($userInfo) {
                $userInfoArray = $userInfo->toArray();

                foreach ($this->encryptedFields as $field) {
                    if (isset($userInfoArray[$field])) {
                        $userInfoArray[$field] = $userInfo->{$field} ? Crypt::decrypt($userInfo->{$field}) : null;
                    }
                }
                $decryptedLogs['userInfo'] = $userInfoArray;
            } else {
                $decryptedLogs['userInfo'] = [];
            }
            $resultJson[] = $decryptedLogs;
        }

        return response()->json([
            'message' => 'Successfully Retrieve Data',
            'result' => $resultJson,
        ], Response::HTTP_OK);
    }

    // HELPER FUNCTION
    public function isDecryptedData($isSensitive, $fields, $fieldsToDecrypt, $notToDecrypts)
    {
        $decryptedData = [];

        // Iterate over each field in the log details
        foreach ($fields as $fieldName => $fieldValue) {
            foreach ($notToDecrypts as $notToDecrypt) {
                if ($notToDecrypt != $fieldName) {
                    // Check if the field is sensitive and needs decryption
                    if ($isSensitive == 1 && in_array($fieldName, $fieldsToDecrypt)) {
                        if (is_array($fieldValue)) {
                            $decOld = isset($fieldValue['oldEnc']) ? Crypt::decrypt($fieldValue['oldEnc']) : null;
                            $decNew = isset($fieldValue['newEnc']) ? Crypt::decrypt($fieldValue['newEnc']) : null;

                            $decryptedData[$fieldName]['old'] = $decOld;
                            $decryptedData[$fieldName]['new'] = $decNew;
                        } else {
                            $decryptedData[$fieldName] = Crypt::decrypt($fieldValue);
                        }
                    } else {
                        $decryptedData[$fieldName] = $fieldValue;
                    }
                } else {
                    // Field is not sensitive or does not need decryption
                    $decryptedData[$fieldName] = $fieldValue;
                }
            }
        }


        return $decryptedData;
    }
}
