<?php

namespace App\Http\Controllers;

use App\Models\UserInfoModel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

use Jenssegers\Agent\Facades\Agent;
use Tymon\JWTAuth\Facades\JWTAuth;

class UserInfoController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $decryptedUserInfos = [];

        $userInfos = UserInfoModel::all();

        foreach ($userInfos as $userInfo) {
            $decryptedUserInfo = [
                'id' => $userInfo && $userInfo->id ? $userInfo->id : null,
                'user_id_hash' => $userInfo && $userInfo->user_id_hash ? $userInfo->user_id_hash : null,
                'first_name' => $userInfo && $userInfo->first_name ? Crypt::decrypt($userInfo->first_name) : null,
                'middle_name' => $userInfo && $userInfo->middle_name ? Crypt::decrypt($userInfo->middle_name) : null,
                'last_name' => $userInfo && $userInfo->last_name ? Crypt::decrypt($userInfo->last_name) : null,
                'contact_number' => $userInfo && $userInfo->contact_number ? Crypt::decrypt($userInfo->contact_number) : null,
                'email' => $userInfo && $userInfo->email ? Crypt::decrypt($userInfo->email) : null,
                'address_1' => $userInfo && $userInfo->address_1 ? Crypt::decrypt($userInfo->address_1) : null,
                'address_2' => $userInfo && $userInfo->address_2 ? Crypt::decrypt($userInfo->address_2) : null,
                'region_code' => $userInfo && $userInfo->region_code ? Crypt::decrypt($userInfo->region_code) : null,
                'province_code' => $userInfo && $userInfo->province_code ? Crypt::decrypt($userInfo->province_code) : null,
                'city_or_municipality_code' => $userInfo && $userInfo->city_or_municipality_code ? Crypt::decrypt($userInfo->city_or_municipality_code) : null,
                'region_name' => $userInfo && $userInfo->region_name ? Crypt::decrypt($userInfo->region_name) : null,
                'province_name' => $userInfo && $userInfo->province_name ? Crypt::decrypt($userInfo->province_name) : null,
                'city_or_municipality_name' => $userInfo && $userInfo->city_or_municipality_name ? Crypt::decrypt($userInfo->city_or_municipality_name) : null,
                'barangay' => $userInfo && $userInfo->barangay ? Crypt::decrypt($userInfo->barangay) : null,
                'description_location' => $userInfo && $userInfo->description_location ? Crypt::decrypt($userInfo->description_location) : null,
            ];

            $decryptedUserInfos[] = $decryptedUserInfo;
        }

        return response()->json(
            [
                'message' => 'Successfully Retrieve Data',
                'result' => $decryptedUserInfos,
            ],
            Response::HTTP_OK
        );
    }

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
     * Display the specified resource.
     */
    public function show(string $id)
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
    public function update(Request $request)
    {
        // Authorize the user
        $user = $this->authorizeUser($request);

        $userAgent = $request->header('User-Agent');
        $jenersAgent = $this->showDeviceInfo();
        // Now you can use $userAgent as needed
        return response()->json(['user_agent' => $userAgent, 'user_device' => $jenersAgent]);

        // // Validation rules
        // $validator = Validator::make($request->all(), [
        //     'first_name' => 'required|string|max:255',
        //     'middle_name' => 'nullable|string|max:255',
        //     'last_name' => 'required|string|max:255',
        //     'contact_number' => 'required|string|max:20',
        //     'email' => 'required|email|max:255',
        //     'address_1' => 'required|string|max:255',
        //     'address_2' => 'nullable|string|max:255',
        //     'region_code' => 'required|string|max:255',
        //     'province_code' => 'required|string|max:255',
        //     'city_or_municipality_code' => 'required|string|max:255',
        //     'region_name' => 'required|string|max:255',
        //     'province_name' => 'required|string|max:255',
        //     'city_or_municipality_name' => 'required|string|max:255',
        //     'barangay' => 'required|string|max:255',
        //     'description_location' => 'nullable|string',
        // ]);

        // // Check if validation fails
        // if ($validator->fails()) {
        //     return response()->json(['error' => $validator->errors()], Response::HTTP_UNPROCESSABLE_ENTITY);
        // }

        // // Find the user by id (replace YourModel with your actual model)
        // $userInfo = UserInfoModel::where('user_id_hash', $user->id_hash)->first();

        // if (!$userInfo) {
        //     return response()->json(['error' => 'User not found'], Response::HTTP_NOT_FOUND);
        // }

        // // Define the fields to loop through
        // $fields = [
        //     'first_name', 'middle_name', 'last_name', 'contact_number',
        //     'email', 'address_1', 'address_2', 'region_code',
        //     'province_code', 'city_or_municipality_code', 'region_name',
        //     'province_name', 'city_or_municipality_name', 'barangay',
        //     'description_location',
        // ];

        // // Loop through the fields for encryption and decryption
        // foreach ($fields as $field) {
        //     // Decrypt existing value
        //     $existingValue = Crypt::decrypt($userInfo->$field);

        //     // Update decrypted value if there are changes
        //     $userInfo->$field = $request->filled($field) ? Crypt::encrypt($request->input($field)) : $existingValue;
        // }

        // // Save the changes
        // if ($userInfo->save()) {
        //     return response()->json(
        //         [
        //             'message' => 'Successfully Update Data',
        //             'result' => $userInfo,
        //         ],
        //         Response::HTTP_OK
        //     );
        // }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }

    // GLOBAL FUNCTIONS
    // Code to check if authenticate users
    public function authorizeUser($request)
    {
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
    }

    public function showDeviceInfo()
    {
        // Get the user agent instance
        $agent = new Agent();

        // Check if the user is using a mobile device
        if (Agent::isMobile()) {
            // Get the device name
            $deviceName = Agent::device();

            // Get the platform (Android, iOS, etc.)
            $platform = Agent::platform();

            // Now you can use $deviceName and $platform as needed
            // ...
        } else {
            // The user is not on a mobile device
            // ...
        }

        // Access device, browser, and operating system information
        // $device = $agent->device();
        // $browser = $agent->browser();
        // $platform = $agent->platform();
        // // Return the information
        // return response()->json([
        //     'device' => $device,
        //     'browser' => $browser,
        //     'platform' => $platform,
        // ]);
    }
}
