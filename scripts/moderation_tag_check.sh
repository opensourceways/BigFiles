#!/bin/bash

PATH_CURRUNT=$(pwd)
CODE_HOME="$PATH_CURRUNT/../../"

function main()
{
    cd $CODE_HOME 2>&1 >/dev/null

   # 遍历当前目录下所有的go文件
   for file in $(find . -name "*.go"); do

       # 使用awk来查找结构体定义
       awk '
       BEGIN { inside_struct = 0; moderation_count = 0; }
       /type [A-Za-z0-9_]+ struct {/ { inside_struct = 1; moderation_count = 0; }
       /}/ {
           if (inside_struct && moderation_count > 1) {
               print "File " FILENAME " has a struct with multiple binding:\"moderationcheck\" tags";
               exit 1;
           }
           inside_struct = 0;
       }
       {
           if (inside_struct && /binding:"moderationcheck"/) {
               moderation_count++;
           }
       }
       ' FILENAME=$file $file

       # 检查awk的退出状态
    if [ $? -ne 0 ]; then
        echo "do check moderation tag failed"
        exit 127
    fi
   done

 echo "All structs are valid"
}

main