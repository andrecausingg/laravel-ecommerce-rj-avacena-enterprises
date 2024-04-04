<?php

namespace App\Http\Controllers;

use Log;
use App\Models\LogsModel;
use Illuminate\Http\Request;
use App\Models\UserInfoModel;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Crypt;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    public function index(Request $request)
    {
        $fields = config('encrypted-fields.EncryptedFields');

        // Logs Array
        $decryptedLogs = [];

        // Get the Attribute
        $logsModel = new LogsModel();
        $fillableAttributesLogs = $logsModel->getFillableAttributes();

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $logs = LogsModel::get();

        foreach ($logs as $log) {
            $detailsJson = json_decode($log['details'], true);

            if (isset($detailsJson['fields'])) {
                $decryptedData = $this->isDecryptedData($detailsJson['fields'], $fields);
                $arrWithParentId = [
                    'user_id' => $detailsJson['user_id'],
                    'fields' => $decryptedData
                ];
            }

            foreach ($fillableAttributesLogs as $fillableAttributeLog) {
                if ($fillableAttributeLog == 'details') {
                    $decryptedLogs[$fillableAttributeLog] = $arrWithParentId;
                } else {
                    $decryptedLogs[$fillableAttributeLog] = $log->$fillableAttributeLog;
                }
            }

            // Retrieve userInfo model
            $userInfo = UserInfoModel::where('user_id', $log['user_id'])->first();
            if ($userInfo) {
                $userInfoArray = $userInfo->toArray();

                foreach ($fields as $field) {
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
            // Check if the field needs to be decrypted
            if (in_array($fieldName, $fieldsToDecrypt)) {
                // Decrypt the field value and store it in the result array
                $decryptedData[$fieldName] = Crypt::decrypt($fieldValue);
            } else {
                $decryptedData[$fieldName] = $fieldValue;
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
