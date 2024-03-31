<?php

namespace App\Http\Controllers;

use App\Models\LogsModel;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LogController extends Controller
{
    public function index(Request $request)
    {
        $fields = config('encrypted-fields');

        // Authorize the user
        $user = $this->authorizeUser($request);

        // Check if authenticated user
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        $decryptedUserInfos = [];

        $logs = LogsModel::get();

        foreach ($logs as $log) {
            foreach ($fields as $field) {
            
            }
            // $decryptedUserInfo = [
            //     'id' => $userInfo && $userInfo->id ? $userInfo->id : null,
            //     'user_id_hash' => $userInfo && $userInfo->user_id_hash ? $userInfo->user_id_hash : null,
            //     'image' => $userInfo && $userInfo->image ? Crypt::decrypt($userInfo->image) : null,
            //     'first_name' => $userInfo && $userInfo->first_name ? Crypt::decrypt($userInfo->first_name) : null,
            //     'middle_name' => $userInfo && $userInfo->middle_name ? Crypt::decrypt($userInfo->middle_name) : null,
            //     'last_name' => $userInfo && $userInfo->last_name ? Crypt::decrypt($userInfo->last_name) : null,
            //     'contact_number' => $userInfo && $userInfo->contact_number ? Crypt::decrypt($userInfo->contact_number) : null,
            //     'email' => $userInfo && $userInfo->email ? Crypt::decrypt($userInfo->email) : null,
            //     'address_1' => $userInfo && $userInfo->address_1 ? Crypt::decrypt($userInfo->address_1) : null,
            //     'address_2' => $userInfo && $userInfo->address_2 ? Crypt::decrypt($userInfo->address_2) : null,
            //     'region_code' => $userInfo && $userInfo->region_code ? Crypt::decrypt($userInfo->region_code) : null,
            //     'province_code' => $userInfo && $userInfo->province_code ? Crypt::decrypt($userInfo->province_code) : null,
            //     'city_or_municipality_code' => $userInfo && $userInfo->city_or_municipality_code ? Crypt::decrypt($userInfo->city_or_municipality_code) : null,
            //     'region_name' => $userInfo && $userInfo->region_name ? Crypt::decrypt($userInfo->region_name) : null,
            //     'province_name' => $userInfo && $userInfo->province_name ? Crypt::decrypt($userInfo->province_name) : null,
            //     'city_or_municipality_name' => $userInfo && $userInfo->city_or_municipality_name ? Crypt::decrypt($userInfo->city_or_municipality_name) : null,
            //     'barangay' => $userInfo && $userInfo->barangay ? Crypt::decrypt($userInfo->barangay) : null,
            //     'description_location' => $userInfo && $userInfo->description_location ? Crypt::decrypt($userInfo->description_location) : null,
            // ];

            // $decryptedUserInfos[] = $decryptedUserInfo;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $logs,
            ],
            Response::HTTP_OK
        );
    }
}
