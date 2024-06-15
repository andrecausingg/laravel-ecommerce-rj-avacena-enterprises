<?php

namespace App\Http\Controllers;

use App\Models\PaymentModel;
use Illuminate\Http\Request;
use App\Models\PurchaseModel;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\InventoryProductModel;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use App\Http\Controllers\Helper\Helper;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response;

class PaymentController extends Controller
{


    protected $helper, $fillable_attr_purchase, $fillable_attr_inventory_product, $fillable_attr_payment;

    public function __construct(Helper $helper, PurchaseModel $fillable_attr_purchase, InventoryProductModel $fillable_attr_inventory_product, PaymentModel $fillable_attr_payment)
    {
        $this->helper = $helper;
        $this->fillable_attr_purchase = $fillable_attr_purchase;
        $this->fillable_attr_inventory_product = $fillable_attr_inventory_product;
        $this->fillable_attr_payment = $fillable_attr_payment;
    }

    public function dashboard(Request $request)
    {

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Retrieve data if not cached
        $dashboardData = [
            'message' => "Successfully retrieve data",
            'stocks' => $this->getTotalStock(),
            'sale' => $this->getSaleTodayMonthYear(),
            'today_transaction' => $this->getTodayTransaction(),
            'chart' => [[
                'year' => $this->getChartSalesYear(),
                'month' => $this->getChartSalesMonth(),
                'week' => $this->getChartSalesWeek(),
                'today' => $this->getChartSalesToday(),
            ]],
        ];


        return response()->json($dashboardData, Response::HTTP_OK);
    }

    public function payment(Request $request)
    {
        $status = 'DONE';

        // Authorize the user
        $user = $this->helper->authorizeUser($request);
        if (empty($user->user_id)) {
            return response()->json(['message' => 'Not authenticated user'], Response::HTTP_UNAUTHORIZED);
        }

        // Validation rules for each item in the array
        $validator = Validator::make($request->all(), [
            'payment_id' => 'required|string',
            'purchase_group_id' => 'required|string',
            'user_id' => 'required|string',
            'money' => 'required|numeric|min:1',
            'eu_device' => 'required|string',
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

        // Validate Eu Device
        $result_validate_eu_device = $this->helper->validateEuDevice($request->eu_device);
        if ($result_validate_eu_device) {
            return $result_validate_eu_device;
        }

        // Start a transaction
        DB::beginTransaction();
        try {
            $decrypted_payment_id = Crypt::decrypt($request->payment_id);
            $decrypted_purchase_group_id = Crypt::decrypt($request->purchase_group_id);
            $decrypted_user_id_customer = Crypt::decrypt($request->user_id);

            $payment = PaymentModel::where('payment_id', $decrypted_payment_id)
                ->where('user_id', $decrypted_user_id_customer)
                ->where('purchase_group_id', $decrypted_purchase_group_id)
                ->where('status', 'NOT PAID')
                ->first();

            if (!$payment) {
                // Rollback the transaction and return the error response
                DB::rollBack();
                return response()->json(['message' => 'Data not found'], Response::HTTP_NOT_FOUND);
            }

            if ($payment->total_amount > $request->money) {
                // Rollback the transaction and return the error response
                DB::rollBack();
                return response()->json(['message' => 'Please input an amount greater than your purchase total amount.'], Response::HTTP_UNPROCESSABLE_ENTITY);
            }

            $paying = $payment->update([
                'money' => $request->money,
                'change' => $request->money - $payment->total_amount,
                'status' => $status,
                'paid_at' => Carbon::now()
            ]);

            if (!$paying) {
                // Rollback the transaction and return the error response
                DB::rollBack();
                return response()->json(['message' => 'Failed to pay purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $purchase_update = PurchaseModel::where('user_id_customer', $decrypted_user_id_customer)
                ->where('purchase_group_id',  $decrypted_purchase_group_id)
                ->update([
                    'status' => $status,
                ]);

            if (!$purchase_update) {
                // Rollback the transaction and return the error response
                DB::rollBack();
                return response()->json(['message' => 'Failed to pay purchase.'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            // Get the items has been update status to DONE
            $purchase_items = PurchaseModel::where('user_id_customer', $decrypted_user_id_customer)
                ->where('purchase_group_id',  $decrypted_purchase_group_id)->where('status',  'DONE')->get();
            foreach ($purchase_items as $purchase_item) {
                $items_done[] = $purchase_item;
            }

            $user_logs['payment'] = $payment;
            $user_logs['items'] = $items_done;
            $eu_device = $request->input('eu_device');

            // Arr Data Logs
            $arr_data_logs = [
                'user_device' => $eu_device,
                'user_id' => $user->user_id,
                'is_sensitive' => 0,
                'is_history' => 0,
                'log_details' => $user_logs,
                'user_action' => 'PAID',
            ];

            // Logs
            $log_result = $this->helper->log($request, $arr_data_logs);
            if ($log_result->getStatusCode() !== Response::HTTP_OK) {
                DB::rollBack();
                return $log_result;
            }

            // Commit the transaction
            DB::commit();

            return response()->json(['message' => 'Purchase successfully paid.'], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Rollback the transaction in case of an exception
            DB::rollBack();
            return response()->json(['message' => 'An error occurred while processing your payment.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    private function getTotalStock()
    {
        // Get the sum of inventory products
        $inventory_product_sum = InventoryProductModel::sum('stocks');

        return $inventory_product_sum;
    }

    private function getSaleTodayMonthYear()
    {
        $arr_sale = [];

        // Get the current month's sales total
        $arr_sale['month']['current'] = PaymentModel::whereYear('paid_at', now()->year)
            ->whereMonth('paid_at', now()->month)
            ->sum('total_amount');

        // Get the previous month's sales total
        $arr_sale['month']['previous'] = PaymentModel::whereYear('paid_at', now()->subMonth()->year)
            ->whereMonth('paid_at', now()->subMonth()->month)
            ->sum('total_amount');

        // Calculate the percentage increase or decrease for monthly sales
        if ($arr_sale['month']['previous'] != 0) {
            $arr_sale['month']['percent_change'] = (($arr_sale['month']['current'] - $arr_sale['month']['previous']) / abs($arr_sale['month']['previous'])) * 100;
        } else {
            $arr_sale['month']['percent_change'] = ($arr_sale['month']['current'] != 0) ? 100 : 0;
        }

        // Get the current year's sales total
        $arr_sale['year']['current'] = PaymentModel::whereYear('paid_at', now()->year)
            ->sum('total_amount');

        // Get the previous year's sales total
        $arr_sale['year']['previous'] = PaymentModel::whereYear('paid_at', now()->subYear()->year)
            ->sum('total_amount');

        // Calculate the percentage increase or decrease for yearly sales
        if ($arr_sale['year']['previous'] != 0) {
            $arr_sale['year']['percent_change'] = (($arr_sale['year']['current'] - $arr_sale['year']['previous']) / abs($arr_sale['year']['previous'])) * 100;
        } else {
            $arr_sale['year']['percent_change'] = ($arr_sale['year']['current'] != 0) ? 100 : 0;
        }

        // Get today's sales total
        $arr_sale['today']['current'] = PaymentModel::whereDate('paid_at', now()->toDateString())
            ->sum('total_amount');

        return [$arr_sale];
    }

    private function getTodayTransaction()
    {
        $arr_today_transaction = [];

        // Get today's transactions
        $today_transactions = PaymentModel::whereDate('created_at', Carbon::now()->toDateString())->get()->toArray();

        // Check if there are any transactions for today
        if (!empty($today_transactions)) {
            // Loop through each transaction
            foreach ($today_transactions as $transaction) {
                // Initialize an array to store transaction attributes
                $transaction_data = [];

                // Assuming $this->fillable_attr_payment->getTodaysTranction() returns an array of attributes to fetch
                foreach ($this->fillable_attr_payment->getTodaysTranction() as $attribute) {
                    // Check if the attribute exists in the transaction
                    if (array_key_exists($attribute, $transaction)) {
                        $value = $transaction[$attribute];

                        // Check if the column needs formatting and value is not null
                        if (in_array($attribute, $this->fillable_attr_payment->arrToConvertToReadableDateTime()) && $value !== null) {
                            $value = $this->helper->convertReadableTimeDate($value);
                        }

                        // Store the attribute and its value in the transaction data array
                        $transaction_data[$attribute] = $value;
                    }
                }

                // Add the transaction data to the array of today's transactions
                $arr_today_transaction[] = $transaction_data;
            }
        }

        return $arr_today_transaction;
    }

    private function getTopSellingProducts()
    {
    }

    private function getChartSalesToday()
    {
        // Get the current date using Carbon
        $current_date = Carbon::now();

        // Array to store hourly sales
        $hourly = [];

        // Loop through each hour of the day from 12 AM to 11 PM
        for ($hour = 0; $hour <= 23; $hour++) {
            // Create a Carbon instance for the current hour
            $current_hour = $current_date->copy()->hour($hour);

            // Get the start and end timestamps for the current hour
            $start_of_hour = $current_hour->copy()->startOfHour();
            $end_of_hour = $current_hour->copy()->endOfHour();

            // Get the sales total for the current hour
            $hourly_total_sales = PaymentModel::whereBetween('paid_at', [$start_of_hour, $end_of_hour])
                ->sum('total_amount');

            // Format the hour in 12-hour format with AM/PM
            $formatted_hour = $current_hour->format('h A');

            // Add the hour and total sales to the array
            $hourly[] = [
                'hour' => $formatted_hour,
                'total' => $hourly_total_sales,
            ];
        }

        return $hourly;
    }

    private function getChartSalesWeek()
    {
        // Array to store daily sales
        $daily_sales = [];

        // Get the start and end of the current week using Carbon
        $startOfWeek = Carbon::now()->startOfWeek();
        $endOfWeek = Carbon::now()->endOfWeek();

        // Loop through each day of the week
        for ($day = $startOfWeek; $day <= $endOfWeek; $day->addDay()) {
            // Get the sales total for the current day
            $total_sales = PaymentModel::whereDate('paid_at', $day)
                ->sum('total_amount');

            // Add the day and total sales to the array
            $daily_sales[] = [
                'day' => $day->format('D'),
                'total' => $total_sales,
            ];
        }

        return $daily_sales;
    }

    private function getChartSalesMonth()
    {
        // Array to store daily sales
        $daily_sales = [];

        // Get the current date using Carbon
        $current_date = Carbon::now();

        // Get the start and end of the current month
        $startOfMonth = $current_date->copy()->startOfMonth();
        $endOfMonth = $current_date->copy()->endOfMonth();

        // Loop through each day of the current month
        for ($day = 1; $day <= $endOfMonth->day; $day++) {
            // Create a Carbon instance for the current day
            $currentDay = Carbon::create($current_date->year, $current_date->month, $day);

            // Get the current day's sales total
            $total_sales = PaymentModel::whereDate('paid_at', $currentDay)
                ->sum('total_amount');

            // Add the day and total sales to the array
            $daily_sales[] = [
                'day' => $currentDay->format('d'),
                'total' => $total_sales,
            ];
        }

        return $daily_sales;
    }

    private function getChartSalesYear()
    {
        // Array to store monthly sales
        $monthly_sales = [];

        // Get the current year using Carbon
        $current_year = Carbon::now()->year;

        // Loop through each month using Carbon
        for ($month = 1; $month <= 12; $month++) {
            // Create a Carbon instance for the first day of the current month
            $startOfMonth = Carbon::create($current_year, $month, 1);
            // Get the last day of the current month
            $endOfMonth = $startOfMonth->copy()->endOfMonth();

            // Get the current month's sales total
            $total_sales = PaymentModel::whereBetween('paid_at', [$startOfMonth, $endOfMonth])
                ->sum('total_amount');

            // Add the month name and total sales to the array
            $monthly_sales[] = [
                'name' => $startOfMonth->format('M'),
                'total' => $total_sales,
            ];
        }

        return $monthly_sales;
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
