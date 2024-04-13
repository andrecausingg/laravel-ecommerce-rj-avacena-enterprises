<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class PurchaseModel extends Model
{
    use HasFactory, SoftDeletes;
    protected $table = 'purchase_tbl';
    protected $primaryKey = 'id';
    protected  $fillable = [
        'purchase_id',
        'purchase_group_id',

        'user_id',
        'inventory_product_id',
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
