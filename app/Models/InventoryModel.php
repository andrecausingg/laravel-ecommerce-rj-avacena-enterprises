<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class InventoryModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'inventory_tbl';

    protected $primaryKey = 'id';
    protected $fillable = [
        'inventory_id',
        'name',
        'category',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function idToUpdate(): array
    {
        return [
            'inventory_id' => 'inv_id-',
        ];
    }

    public function arrToStores(): array
    {
        return [
            'name', 'category'
        ];
    }

    public function arrToUpdates(): array
    {
        return [
            'name', 'category'
        ];
    }

    public function unsetActions(): array
    {
        return [
            'destroy',
        ];
    }

    public function arrToConvertToReadableDateTime(): array
    {
        return  [
            'created_at', 'updated_at', 'deleted_at'
        ];
    }

    public function arrModelWithId(): array
    {
        return [
            'InventoryProductModel'  => ['inventory_id']
        ];
    }

    public function getApiAccountCrudSettings()
    {
        $prefix = 'inventory/parent/';
        $api_with_payloads = [
            'update' => $this->arrToUpdates(),
            'destroy' => ['inventory_id', 'eu_device']
        ];
        $method = [
            'update' => 'POST',
            'destroy' => 'DELETE',
        ];
        $button_names = [
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

        return compact('prefix', 'api_with_payloads', 'method', 'button_names', 'icons', 'actions');
    }

    public function getApiAccountRelativeSettings()
    {
        $prefix = 'inventory/parent/';
        $api_with_payloads = [
            'store' => $this->arrToStores(),
            'show/' => [
                'id',
            ],
            'product/show/' => [
                'id',
            ]
        ];

        $method = [
            'store' => 'POST',
            'show/' => 'GET',
            'product/show/' => 'GET',
        ];

        $button_names = [
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

        return compact('prefix', 'api_with_payloads', 'method', 'button_names', 'icons', 'actions');
    }

    public function getViewRowTable()
    {
        $url = 'inventory/parent/';
        $method = 'GET';
        return compact('url',  'method');
    }
}
