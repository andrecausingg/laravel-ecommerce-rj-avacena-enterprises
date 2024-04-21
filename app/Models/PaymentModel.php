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

        'payment_method', 
        'voucher',
        'total_discounted_amount',
        'total_amount',
        'money',
        'change',
        'status',

        'deleted_at',
        'created_at',
        'updated_at',
    ];

    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }
}
