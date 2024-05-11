<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class PaymentModel extends Model
{
    use HasFactory, SoftDeletes;
    protected $table = 'payment_tbl';
    protected $primaryKey = 'id';
    protected  $fillable = [
        'payment_id',

        'user_id',
        'purchase_group_id',
        'voucher_id',

        'payment_method',
        'total_discounted_amount',
        'total_amount',
        'money',
        'change',
        'status',

        'paid_at',
        'deleted_at',
        'created_at',
        'updated_at',
    ];

    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function getTodaysTranction(): array
    {
        return [
            'user_id',
            'created_at',
            'total_amount',
            'status',
        ];
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }
}
