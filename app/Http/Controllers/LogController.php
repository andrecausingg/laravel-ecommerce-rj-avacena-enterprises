<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Crypt;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    protected $encryptedFields, $fillableAttributes;

    public function __construct()
    {
        $this->encryptedFields = config('encrypted-fields.EncryptedFields');

        // Get the Attribute
        $logsModel = new LogsModel();
        $this->fillableAttributes = $logsModel->getFillableAttributes();
    }

    public function index(Request $request)
    {
        $decryptedLogs = [];
        $resultJson = [];

        $user = $this->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $logs = LogsModel::get();
        foreach ($logs as $log) {
            $detailsJson = json_decode($log['details'], true);

            if (isset($detailsJson['fields'])) {
                $decryptedData = $this->isDecryptedData($detailsJson['fields'], $this->encryptedFields);
                $arrWithParentId = [
                    'user_id' => $detailsJson['user_id'],
                    'fields' => $decryptedData
                ];
            }

            foreach ($this->fillableAttributes as $fillableAttribute) {
                if ($fillableAttribute == 'details') {
                    $decryptedLogs[$fillableAttribute] = $arrWithParentId;
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
    public function isDecryptedData($fields, $fieldsToDecrypt)
    {
        $decryptedData = [];

        // Iterate over each field in the log details
        foreach ($fields as $fieldName => $fieldValue) {

            if (is_array($fieldValue)) {
                // If $fieldValue is an array, decrypt 'oldEnc' and 'newEnc'
                $decOld = isset($fieldValue['oldEnc']) ? Crypt::decrypt($fieldValue['oldEnc']) : $fieldValue['old'];
                $decNew = isset($fieldValue['newEnc']) ? Crypt::decrypt($fieldValue['newEnc']) : $fieldValue['new'];
                $decryptedData[$fieldName]['old'] = $decOld;
                $decryptedData[$fieldName]['new'] = $decNew;
            } else {
                // If $fieldValue is not an array, decrypt it if needed
                if (in_array($fieldName, $fieldsToDecrypt)) {
                    // Decrypt the field value and store it in the result array
                    $decryptedData[$fieldName] = Crypt::decrypt($fieldValue);
                } else {
                    $decryptedData[$fieldName] = $fieldValue;
                }
            }
        }

        return $decryptedData;
    }

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
}
