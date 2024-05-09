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

        'inventory_id',

        'item_code',
        'image',
        'name',
        'category',
        'description',
        'supplier_name',
        'design',
        'size',
        'color',

        'retail_price',
        'discounted_price',
        'unit_supplier_price',

        'stock',

        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function arrToStores(): array
    {
        return [
            'inventory_id',
            'item_code',
            'image',
            'name',
            'category',
            'description',
            'supplier_name',
            'design',
            'size',
            'color',
            'retail_price',
            'discounted_price',
            'unit_supplier_price',
            'stock',
        ];
    }
    public function arrToUpdates(): array
    {
        return [
            'inventory_id',
            'item_code',
            'image',
            'name',
            'category',
            'description',
            'supplier_name',
            'design',
            'size',
            'color',
            'retail_price',
            'discounted_price',
            'unit_supplier_price',
            'stock',
        ];
    }

    public function idToUpdate(): array
    {
        return [
            'inventory_product_id' => 'inv_product_id-',
        ];
    }

    public function arrModelWithId(): array
    {
        return [
            'PurchaseModel'  => ['inventory_id']
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'inventory/product/';
        $apiWithPayloads = [
            'update' => $this->arrToUpdates(),
            'destroy' => ['inventory_id', 'eu_device']
        ];
        $methods = [
            'update' => 'POST',
            'destroy' => 'DELETE',
        ];
        $buttonNames = [
            'update' => 'update',
            'destroy' => 'delete',
        ];
        $icons = [
            'update' => null,
            'destroy' =>  null,
        ];
        $actions = [
            'update' => 'modal',
            'destroy' => 'modal',
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'inventory/product/';
        $apiWithPayloads = [
            'store' => $this->arrToStores(),
            'show/' => [
                'id',
            ],
            'product/show/' => [
                'id',
            ]
        ];

        $methods = [
            'store' => 'POST',
            'show/' => 'GET',
            'product/show/' => 'GET',
        ];

        $buttonNames = [
            'store' => 'create',
            'show/' => null,
            'product/show/' => null,
        ];

        $icons = [
            'store' => null,
            'show/' => null,
            'product/show/' => null,
        ];

        $actions = [
            'store' => 'modal',
            'show/' => null,
            'product/show/' => 'GET',
        ];

        return compact('prefix', 'apiWithPayloads', 'methods', 'buttonNames', 'icons', 'actions');
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }
}
