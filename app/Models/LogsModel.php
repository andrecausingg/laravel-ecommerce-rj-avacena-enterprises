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
    protected $fillable = [
        'log_id',
        'user_id',
        'ip_address',
        'user_action',
        'details',
        'user_device',
        'deleted_at',
        'created_at',
        'updated_at',
    ];
    protected $dates = ['deleted_at'];
}
