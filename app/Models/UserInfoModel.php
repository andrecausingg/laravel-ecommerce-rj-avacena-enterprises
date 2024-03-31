<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class UserInfoModel extends Model
{
    use HasFactory;
    use SoftDeletes;
    protected $table = 'users_info_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'user_id',
        'image',
        'first_name',
        'middle_name',
        'last_name',
        'contact_number',
        'email',
        'address_1',
        'address_2',
        'region_code',
        'province_code',
        'city_or_municipality_code',
        'region_name',
        'province_name',
        'city_or_municipality_name',
        'barangay',
        'deleted_at',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];

}
