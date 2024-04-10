<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class InventoryProductModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'inventory_product_tbl';

    protected $primaryKey = 'id';
    protected $fillable = [
        'inventory_product_id',
        'inventory_group_id',
        
        'item_code',
        'image',
        'name',
        'description',
        'is_refund',
        'category',

        'retail_price',
        'discounted_price',
        'stock',

        'supplier_name',
        'unit_supplier_price',

        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }
}
