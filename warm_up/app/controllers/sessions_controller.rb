

class SessionsController < ApplicationController



    def create
        @user = User.find_by_credentials(params[user][email], params[user][password])
        if @user 
            login(@user)
            redirect_to user_url(@user.id)

        else
           render :new
        end

    end
    def destroy
        logout
        redirect_to new_session_url
    end
end
  