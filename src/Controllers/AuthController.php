<?php

namespace Encore\Admin\Controllers;

use App\Model\Account;
use App\Model\Handicap;
use App\Model\Result;
use App\Service\HandicapService;
use Encore\Admin\Auth\Database\Administrator;
use Encore\Admin\Facades\Admin;
use Encore\Admin\Form;
use Encore\Admin\Layout\Content;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Show the login page.
     *
     * @return \Illuminate\Contracts\View\Factory|Redirect|\Illuminate\View\View
     */
    public function getLogin()
    {
        if ($this->guard()->check()) {
            return redirect($this->redirectPath());
        }

        return view('admin::login');
    }

    /**
     * Handle a login request.
     *
     * @param Request $request
     *
     * @return mixed
     */
    public function postLogin(Request $request)
    {
        $credentials = $request->only([$this->username(), 'password']);

        /** @var \Illuminate\Validation\Validator $validator */
        $validator = Validator::make($credentials, [
            $this->username() => 'required',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return back()->withInput()->withErrors($validator);
        }

        if ($this->guard()->attempt($credentials)) {
            $roles = Admin::user()->roles;
            if (!empty($roles) && isset($roles[0]['slug'])) {
                $role = $roles[0]['slug'];
                $redis = Redis::connection('default');
                $userId = Admin::user()->id;
                $currentTime = time();
                $expireTime = $currentTime + 86400;

                if ('Cashier' == $role) {
                    $cashierLoginLock = $redis->setnx('cashier_login_lock', $userId);
                    if ($cashierLoginLock) {
                        $redis->expireAt('cashier_login_lock', $expireTime);

                        $cashierBillLock = $redis->setnx('cashier_bill_lock', $userId);
                        if ($cashierBillLock) {
                            $redis->expireAt('cashier_bill_lock', $expireTime);
                            $this->cashierBill();
                        } else {
                            $redis->del('cashier_login_lock');
                            $lastLoginCashier = $redis->get('last_login_cashiers');
                            if ($userId != $lastLoginCashier) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '上次登录用户未完成结账，无法登录'
                                ]);
                            }
                        }
                        return redirect('/account/cashier');
                    } else {
                        $loginCashierId = $redis->get('cashier_login_lock');
                        if ($loginCashierId != $userId) {
                            $this->guard()->logout();
                            $request->session()->invalidate();
                            return back()->withInput()->withErrors([
                                $this->username() => '已有出纳员用户登录，无法登录'
                            ]);
                        } else {
                            return redirect('/account/cashier');
                        }
                    }
                } elseif ('Banker' == $role) {
                    // 收银员
                    $bankerLoginLock = $redis->setnx('banker_login_lock', $userId);
                    if ($bankerLoginLock) {
                        $redis->expireAt('banker_login_lock', $expireTime);

                        $bankerBillLock = $redis->setnx('banker_bill_lock', $userId);
                        if ($bankerBillLock) {
                            $redis->expireAt('banker_bill_lock', $expireTime);
                            $result = $this->bankerBill();
                            if (0 == $result['status']) {
                                return redirect('/result/cash-handover');
                            }
                        } else {
                            $redis->del('banker_login_lock');
                            $lastLoginBanker = $redis->get('last_login_banker');
                            if ($userId != $lastLoginBanker) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '上次登录用户未完成结账，无法登录'
                                ]);
                            }
                        }
                        return redirect('/account/cash');
                    } else {
                        $loginBankerId = $redis->get('banker_login_lock');
                        if ($loginBankerId != $userId) {
                            $this->guard()->logout();
                            $request->session()->invalidate();
                            return back()->withInput()->withErrors([
                                $this->username() => '已有银行家用户登录，无法登录'
                            ]);
                        } else {
                            return redirect('/account/cash');
                        }
                    }
                } elseif ('Manager' == $role) {
                    $cashierLoginLock = $redis->setnx('cashier_login_lock', $userId);
                    $bankerLoginLock = $redis->setnx('banker_login_lock', $userId);
                    if ($cashierLoginLock && $bankerLoginLock) {
                        $redis->expireAt('cashier_login_lock', $expireTime);
                        $redis->expireAt('banker_login_lock', $expireTime);
                        $cashierBillLock = $redis->setnx('cashier_bill_lock', $userId);
                        if ($cashierBillLock) {
                            $redis->expireAt('cashier_bill_lock', $expireTime);
                            $this->cashierBill();
                        } else {
                            $redis->del(['cashier_login_lock', 'banker_login_lock']);
                            $lastLoginCashier = $redis->get('last_login_cashier');
                            if ($userId != $lastLoginCashier) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '上次登录用户未完成结账，无法登录'
                                ]);
                            }
                        }

                        $bankerBillLock = $redis->setnx('banker_bill_lock', $userId);
                        if ($bankerBillLock) {
                            $redis->expireAt('banker_bill_lock', $expireTime);
                            $result = $this->bankerBill();
                            if (0 == $result['status']) {
                                return redirect('/result/cash-handover');
                            }
                        } else {
                            $redis->del(['cashier_login_lock', 'banker_login_lock']);
                            $lastLoginBanker = $redis->get('last_login_banker');
                            if ($userId != $lastLoginBanker) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '上次登录用户未完成结账，无法登录'
                                ]);
                            }
                        }
                        return redirect('/account/cash');
                    } else {
                        if ($cashierLoginLock) {
                            $redis->del('cashier_login_lock');
                        } else {
                            $loginCashierId = $redis->get('cashier_login_lock');
                            if ($loginCashierId != $userId) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '已有出纳员用户登录，无法登录'
                                ]);
                            }
                        }

                        if ($bankerLoginLock) {
                            $redis->del('banker_login_lock');
                        } else {
                            $loginBankerId = $redis->get('banker_login_lock');
                            if ($loginBankerId == $userId) {
                                $this->guard()->logout();
                                $request->session()->invalidate();
                                return back()->withInput()->withErrors([
                                    $this->username() => '已有银行家色用户登录，无法登录'
                                ]);
                            }
                        }
                    }
                }
            }
            return $this->sendLoginResponse($request);
        }

        return back()->withInput()->withErrors([
            $this->username() => $this->getFailedLoginMessage(),
        ]);
    }

    /**
     * User logout.
     *
     * @return Redirect
     */
    public function getLogout(Request $request)
    {
        $roles = Admin::user()->roles;
        $userId = Admin::user()->id;
        if (!empty($roles) && isset($roles[0]['slug'])) {
            $role = $roles[0]['slug'];
            $redis = Redis::connection('default');
            if ('Cashier' == $role) {
                $redis->del('cashier_login_lock');
                $redis->set('last_login_cashier', $userId);
            } elseif ('Banker' == $role) {
                $bankerCheckLock = $redis->setnx('banker_check_balance', 1);
                if ($bankerCheckLock) {
                    $redis->del(['banker_bill_lock', 'banker_check_balance']);
                }
                $redis->del('banker_login_lock');
                $redis->set('last_login_banker', $userId);
            } elseif ('Manager' == $role) {
                $redis->del('cashier_login_lock');
                $redis->del('banker_login_lock');
                $redis->set('last_login_cashier', $userId);
                $redis->set('last_login_banker', $userId);
            }
        }

        $this->guard()->logout();

        $request->session()->invalidate();

        return redirect(config('admin.route.prefix'));
    }

    /**
     * User setting page.
     *
     * @return mixed
     */
    public function getSetting()
    {
        return Admin::content(function (Content $content) {
            $content->header(trans('admin.user_setting'));
            $form = $this->settingForm();
            $form->tools(
                function (Form\Tools $tools) {
                    $tools->disableBackButton();
                    $tools->disableListButton();
                }
            );
            $content->body($form->edit(Admin::user()->id));
        });
    }

    /**
     * Update user setting.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function putSetting()
    {
        return $this->settingForm()->update(Admin::user()->id);
    }

    /**
     * Model-form for user setting.
     *
     * @return Form
     */
    protected function settingForm()
    {
        return Administrator::form(function (Form $form) {
            $form->display('username', trans('admin.username'));
            $form->text('name', trans('admin.name'))->rules('required');
            $form->image('avatar', trans('admin.avatar'));
            $form->password('password', trans('admin.password'))->rules('confirmed|required');
            $form->password('password_confirmation', trans('admin.password_confirmation'))->rules('required')
                ->default(function ($form) {
                    return $form->model()->password;
                });

            $form->setAction(admin_base_path('auth/setting'));

            $form->ignore(['password_confirmation']);

            $form->saving(function (Form $form) {
                if ($form->password && $form->model()->password != $form->password) {
                    $form->password = bcrypt($form->password);
                }
            });

            $form->saved(function () {
                admin_toastr(trans('admin.update_succeeded'));

                return redirect(admin_base_path('auth/setting'));
            });
        });
    }

    /**
     * @return string|\Symfony\Component\Translation\TranslatorInterface
     */
    protected function getFailedLoginMessage()
    {
        return Lang::has('auth.failed')
            ? trans('auth.failed')
            : 'These credentials do not match our records.';
    }

    /**
     * Get the post login redirect path.
     *
     * @return string
     */
    protected function redirectPath()
    {
        if (method_exists($this, 'redirectTo')) {
            return $this->redirectTo();
        }

        return property_exists($this, 'redirectTo') ? $this->redirectTo : config('admin.route.prefix');
    }

    /**
     * Send the response after the user was authenticated.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\Response
     */
    protected function sendLoginResponse(Request $request)
    {
        admin_toastr(trans('admin.login_successful'));
        $request->session()->regenerate();

        return redirect()->intended($this->redirectPath());
    }

    private function cashierBill()
    {
        $result = Result::where('type', 2)
            ->select(['status', 'result_id'])
            ->orderBy('created_at', 'DESC')
            ->first();
        if (!empty($result) && 0 == $result['status']) {
            $handicaps = Handicap::where('status', 1)
                ->select(['handicap_id', 'handicap_slug', 'handicap_balance', 'handicap_name'])
                ->get();

            $errorData = [];

            foreach ($handicaps as $handicap) {
                $handicapInfo = HandicapService::getHandicapInfo($handicap['handicap_slug']);
                if (isset($handicapInfo['ScoreNum'])
                    && $handicapInfo['ScoreNum'] != $handicap['handicap_balance']) {
                    $errorData[] = [
                        'handicap_name' => $handicap['handicap_name'],
                        'handicap_balance' => $handicap['handicap_balance'],
                        'real_balance' => $handicapInfo['ScoreNum'],
                    ];
                    $diff = $handicap['handicap_balance'] - $handicapInfo['ScoreNum'];
                    $handicap['handicap_balance'] = $handicapInfo['ScoreNum'];
                    $handicap->push();

                    Account::create([
                        'in' => $diff,
                        'type' => config('type.error_score'),
                        'handicap_balance' => $handicap['handicap_balance'],
                        'status' => config('status.finish'),
                        'finish_time' => date('Y-m-d H:i:s'),
                        'remark' => '错帐记录',
                    ]);
                }
            }

            $redis = Redis::connection('default');
            $redis->set('handicap_error', json_encode($errorData));
            $result->status = 1;
            $result->push();
        }

        return $result;
    }

    /**
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector
     */
    private function bankerBill()
    {
        $result = Result::where('type', 1)
            ->select(['status', 'result_id'])
            ->orderBy('created_at', 'DESC')
            ->first();

        return $result;
    }

    /**
     * Get the login username to be used by the controller.
     *
     * @return string
     */
    protected function username()
    {
        return 'username';
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard('admin');
    }
}