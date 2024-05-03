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
                $decryptedData = $this->isDecryptedData($log->is_sensitive, $detailsJson['fields'], $this->fillableAttrLogs->encryptedFields(), $this->fillableAttrLogs->notToDecrypt());

                // Decrypted data save on fields
                $arrWithParentId = [
                    'fields' => $decryptedData
                ];
            }

            foreach ($this->fillableAttrLogs->getFillableAttributes() as $fillableAttrLog) {
                if ($fillableAttrLog == 'details') {
                    $decryptedLogs[$fillableAttrLog] = $arrWithParentId;
                } else if ($fillableAttrLog == 'user_device') {
                    $decryptedLogs[$fillableAttrLog] = json_decode($log->$fillableAttrLog, true);
                } else {
                    $decryptedLogs[$fillableAttrLog] = $log->$fillableAttrLog;
                }
            }

            // Retrieve userInfo model
            $userInfo = UserInfoModel::where('user_id', $log['user_id'])->first();
            if ($userInfo) {
                $userInfoArray = $userInfo->toArray();

                foreach ($this->fillableAttrLogs->encryptedFields() as $encryptedField) {
                    if (isset($userInfoArray[$encryptedField])) {
                        $userInfoArray[$encryptedField] = $userInfo->{$encryptedField} ? Crypt::decrypt($userInfo->{$encryptedField}) : null;
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
                            $decOld = isset($fieldValue['oldEnc']) ? Crypt::decrypt($fieldValue['oldEnc']) : (isset($fieldValue['old']) ? Crypt::decrypt($fieldValue['old']) : null);
                            $decNew = isset($fieldValue['newEnc']) ? Crypt::decrypt($fieldValue['newEnc']) : (isset($fieldValue['new']) ? Crypt::decrypt($fieldValue['new']) : null);

                            $decryptedData[$fieldName]['old'] = $decOld;
                            $decryptedData[$fieldName]['new'] = $decNew;
                        } else {
                            $decryptedData[$fieldName] = $fieldValue !== null ? Crypt::decrypt($fieldValue) : null;
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

        Log::info($decryptedData);


        return $decryptedData;
    }
}
