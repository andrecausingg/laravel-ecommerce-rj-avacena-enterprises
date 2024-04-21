<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use App\Models\PurchaseModel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PaymentController extends Controller
{

    public function payment(Request $request)
    {
        $status = 'DONE';

        // Authorize the user
        $user = $this->authorizeUser($request);

        if (empty($user->user_id)) {
            return response()->json(
                [
                    'message' => 'Not authenticated user',
                ],
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'money' => 'required|numeric|min:1',
            'payment_id' => 'required|string',
            'user_id' => 'required|string',
            'purchase_group_id' => 'required|string',
        ]);

        // Check if validation fails
        if ($validator->fails()) {
            return response()->json(
                [
                    'message' => $validator->errors(),
                ],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        $payment = PaymentModel::where('payment_id', $request->payment_id)
            ->where('user_id', $request->user_id)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->first();

        if (!$payment) {
            return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
        }

        if ($payment->total_amount > $request->money) {
            return response()->json(['message' => 'Please input an amount greater than your purchase total amount.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $paying = $payment->update([
            'money' => $request->money,
            'change' => $request->money - $payment->total_amount,
            'status' => $status,
        ]);

        if (!$paying) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $payment = PurchaseModel::where('user_id_customer', $request->user_id)
            ->where('purchase_group_id', $request->purchase_group_id)
            ->update([
                'status' => $status
            ]);

        if (!$payment) {
            return response()->json(['message' => 'Failed to paid purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return response()->json(['message' => 'Purchase successfully paid.'], Response::HTTP_OK);
    }

    // GLOBAL Auth
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


    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
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
}
