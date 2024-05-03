<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class LogsModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'logs_tbl';
    protected $primaryKey = 'id';
    protected  $fillable = [
        'log_id',
        'user_id',
        'is_sensitive',
        'ip_address',
        'user_action',
        'details',
        'user_device',
        'deleted_at',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

    public function getFillableAttributes(): array
    {
        return $this->fillable;
    }

    public function encryptedFields(): array
    {
        return [
            // USER ACC MODEL LOGS
            'email', 'password',
            'old_password', 'new_password',
            'old_email', 'new_email',

            //USER INFO MODEL LOGS
            'image', 'first_name', 'middle_name', 'last_name', 'contact_number',
            'address_1', 'address_2', 'region_code',
            'province_code', 'city_or_municipality_code', 'region_name',
            'province_name', 'city_or_municipality_name', 'barangay',
            'description_location',
        ];
    }

    public function notToDecrypt(): array
    {
        return [
            'user_id', 'id', 'deleted_at', 'created_at', 'updated_at'
        ];
    }
}
