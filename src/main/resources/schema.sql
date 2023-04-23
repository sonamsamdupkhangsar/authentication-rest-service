CREATE TABLE if not exists Authentication (authentication_id varchar PRIMARY KEY, password varchar, user_id UUID,
  signin_source_id UUID, active boolean, access_date_time timestamp);